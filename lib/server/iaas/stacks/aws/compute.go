/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package aws

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"

	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/pricing"

	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

type portDef struct {
	protocol string
	fromPort int64
	toPort   int64
}

// CreateKeyPair creates a keypair and upload it to AWS
func (s *Stack) CreateKeyPair(name string) (_ *abstract.KeyPair, xerr fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "('%s')", name).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	keypair, xerr := abstract.NewKeyPair(name)
	if xerr != nil {
		return nil, xerr
	}
	_, err := s.EC2Service.ImportKeyPair(&ec2.ImportKeyPairInput{
		KeyName:           aws.String(name),
		PublicKeyMaterial: []byte(keypair.PublicKey),
	})
	if err != nil {
		return nil, normalizeError(err)
	}
	return keypair, nil
}

// ImportKeyPair imports an existing resources.KeyPair to AWS (not in the interface yet, but will come soon)
func (s *Stack) ImportKeyPair(keypair *abstract.KeyPair) (xerr fail.Error) {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	if keypair == nil {
		return fail.InvalidParameterError("keypair", "cannot be nil")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%v)", keypair).
		WithStopwatch().
		Entering().
		Exiting()
	defer fail.OnExitLogError(&xerr)

	_, err := s.EC2Service.ImportKeyPair(&ec2.ImportKeyPairInput{
		KeyName:           aws.String(keypair.Name),
		PublicKeyMaterial: []byte(keypair.PublicKey),
	})
	return normalizeError(err)
}

// GetKeyPair loads a keypair from AWS
// Note: the private key is not stored by AWS...
func (s *Stack) InspectKeyPair(id string) (_ *abstract.KeyPair, xerr fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).
		WithStopwatch().
		Entering().
		Exiting()
	defer fail.OnExitLogError(&xerr)

	out, err := s.EC2Service.DescribeKeyPairs(&ec2.DescribeKeyPairsInput{
		KeyNames: []*string{aws.String(id)},
	})
	if err != nil {
		return nil, fail.Wrap(normalizeError(err), "failed to get keypair '%s'", id)
	}
	if len(out.KeyPairs) == 0 {
		return nil, fail.NotFoundError("failed to find keypair '%s'", id)
	}

	kp := out.KeyPairs[0]
	return &abstract.KeyPair{
		ID:         aws.StringValue(kp.KeyName),
		Name:       aws.StringValue(kp.KeyName),
		PrivateKey: "",
		PublicKey:  aws.StringValue(kp.KeyFingerprint),
	}, nil
}

// ListKeyPairs lists keypairs stored in AWS
func (s *Stack) ListKeyPairs() (_ []abstract.KeyPair, xerr fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute")).
		WithStopwatch().
		Entering().
		Exiting()
	defer fail.OnExitLogError(&xerr)

	out, err := s.EC2Service.DescribeKeyPairs(&ec2.DescribeKeyPairsInput{})
	if err != nil {
		return nil, normalizeError(err)
	}
	var keys []abstract.KeyPair
	for _, kp := range out.KeyPairs {
		keys = append(keys, abstract.KeyPair{
			ID:         aws.StringValue(kp.KeyName),
			Name:       aws.StringValue(kp.KeyName),
			PrivateKey: "",
			PublicKey:  aws.StringValue(kp.KeyFingerprint),
		})
	}
	return keys, nil
}

// DeleteKeyPair deletes a keypair from AWS
func (s *Stack) DeleteKeyPair(id string) (xerr fail.Error) {
	if s == nil {
		return fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	_, err := s.EC2Service.DeleteKeyPair(&ec2.DeleteKeyPairInput{
		KeyName: aws.String(id),
	})

	return normalizeError(err)
}

// ListAvailabilityZones lists AWS availability zones available
func (s *Stack) ListAvailabilityZones() (_ map[string]bool, xerr fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute")).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	zones := make(map[string]bool)

	ro, err := s.EC2Service.DescribeAvailabilityZones(&ec2.DescribeAvailabilityZonesInput{})
	if err != nil {
		return zones, normalizeError(err)
	}
	if ro != nil {
		for _, zone := range ro.AvailabilityZones {
			zoneName := aws.StringValue(zone.ZoneName)
			if zoneName != "" {
				zones[zoneName] = aws.StringValue(zone.State) == "available"
			}
		}
	}

	return zones, nil
}

// ListRegions lists regions available in AWS
func (s *Stack) ListRegions() (_ []string, xerr fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute")).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	var regions []string

	ro, err := s.EC2Service.DescribeRegions(&ec2.DescribeRegionsInput{})
	if err != nil {
		return regions, normalizeError(err)
	}
	if ro != nil {
		for _, region := range ro.Regions {
			regions = append(regions, aws.StringValue(region.RegionName))
		}
	}

	return regions, nil
}

// GetImage loads information about an image stored in AWS
func (s *Stack) InspectImage(id string) (_ *abstract.Image, xerr fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	imagesList, xerr := s.ListImages()
	if xerr != nil {
		return nil, xerr
	}
	for _, res := range imagesList {
		if res.ID == id {
			return &res, nil
		}
	}

	return nil, abstract.ResourceNotFoundError("Image", id)
}

// GetTemplate loads information about a template stored in AWS
func (s *Stack) InspectTemplate(id string) (template *abstract.HostTemplate, xerr fail.Error) {
	template = &abstract.HostTemplate{}
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	prods, err := s.PricingService.GetProducts(&pricing.GetProductsInput{
		Filters: []*pricing.Filter{
			{
				Field: aws.String("ServiceCode"),
				Type:  aws.String("TERM_MATCH"),
				Value: aws.String("AmazonEC2"),
			},
			{
				Field: aws.String("operatingSystem"),
				Type:  aws.String("TERM_MATCH"),
				Value: aws.String("Linux"),
			},
			{
				Field: aws.String("instanceType"),
				Type:  aws.String("TERM_MATCH"),
				Value: aws.String(id),
			},
		},
		MaxResults:  aws.Int64(100),
		ServiceCode: aws.String("AmazonEC2"),
	})
	if err != nil {
		return template, normalizeError(err)
	}

	for _, price := range prods.PriceList {
		jsonPrice, err := json.Marshal(price)
		if err != nil {
			continue
		}
		price := Price{}
		err = json.Unmarshal(jsonPrice, &price)
		if err != nil {
			continue
		}

		tpl := abstract.HostTemplate{
			ID:        price.Product.Attributes.InstanceType,
			Name:      price.Product.Attributes.InstanceType,
			Cores:     ParseNumber(price.Product.Attributes.Vcpu, 1),
			GPUNumber: ParseNumber(price.Product.Attributes.Gpu, 0),
			DiskSize:  int(ParseStorage(price.Product.Attributes.Storage)),
			RAMSize:   float32(ParseMemory(price.Product.Attributes.Memory)),
		}

		template = &tpl
		break
	}

	return template, nil
}

// createFilters ...
func createFilters() []*ec2.Filter {
	filters := []*ec2.Filter{
		{
			Name:   aws.String("state"),
			Values: []*string{aws.String("available")},
		},
		{
			Name:   aws.String("architecture"),
			Values: []*string{aws.String("x86_64")},
		},
		{
			Name:   aws.String("virtualization-type"),
			Values: []*string{aws.String("hvm")},
		},
		{
			Name:   aws.String("root-device-type"),
			Values: []*string{aws.String("ebs")},
		},
		{
			Name:   aws.String("ena-support"),
			Values: []*string{aws.String("true")},
		},
	}

	// FIXME: AWS CentOS AND Others
	owners := []*string{
		aws.String("099720109477"), // Ubuntu
		aws.String("013116697141"), // Fedora
		aws.String("379101102735"), // Debian
		aws.String("161831738826"), // Centos 7 with ENA
		aws.String("057448758665"), // Centos 7
		aws.String("679593333241"), // Centos 6 AND Others
		aws.String("595879546273"), // CoreOS
		aws.String("902460189751"), // Gentoo
		aws.String("341857463381"), // Gentoo
	}
	filters = append(filters, &ec2.Filter{
		Name:   aws.String("owner-id"),
		Values: owners,
	})
	return filters
}

// ListImages lists available image
func (s *Stack) ListImages() (_ []abstract.Image, xerr fail.Error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute")).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	var images []abstract.Image

	filters := []*ec2.Filter{
		{
			Name:   aws.String("architecture"),
			Values: []*string{aws.String("x86_64")},
		},
		{
			Name:   aws.String("state"),
			Values: []*string{aws.String("available")},
		},
	}

	// Added filtering by owner-id
	filters = append(filters, createFilters()...)

	iout, err := s.EC2Service.DescribeImages(&ec2.DescribeImagesInput{
		Filters: filters,
	})
	if err != nil {
		return images, normalizeError(err)
	}
	if iout != nil {
		for _, image := range iout.Images {
			if image != nil {
				if !aws.BoolValue(image.EnaSupport) {
					logrus.Warnf("ENA filtering does NOT actually work !")
				}

				images = append(images, abstract.Image{
					ID:          aws.StringValue(image.ImageId),
					Name:        aws.StringValue(image.Name),
					Description: aws.StringValue(image.Description),
					StorageType: aws.StringValue(image.RootDeviceType),
				})
			}
		}
	}

	return images, nil
}

// ListTemplates lists templates stored in AWS
func (s *Stack) ListTemplates() (templates []abstract.HostTemplate, xerr fail.Error) {
	templates = []abstract.HostTemplate{}
	if s == nil {
		return templates, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute")).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	prods, err := s.PricingService.GetProducts(&pricing.GetProductsInput{
		Filters: []*pricing.Filter{
			{
				Field: aws.String("ServiceCode"),
				Type:  aws.String("TERM_MATCH"),
				Value: aws.String("AmazonEC2"),
			},
			{
				Field: aws.String("operatingSystem"),
				Type:  aws.String("TERM_MATCH"),
				Value: aws.String("Linux"),
			},
		},
		MaxResults:  aws.Int64(100),
		ServiceCode: aws.String("AmazonEC2"),
	})
	if err != nil {
		return templates, normalizeError(err)
	}

	templates = make([]abstract.HostTemplate, 0, len(prods.PriceList))
	for _, price := range prods.PriceList {
		jsonPrice, err := json.Marshal(price)
		if err != nil {
			continue
		}
		price := Price{}
		err = json.Unmarshal(jsonPrice, &price)
		if err != nil {
			continue
		}

		tpl := abstract.HostTemplate{
			ID:        price.Product.Attributes.InstanceType,
			Name:      price.Product.Attributes.InstanceType,
			Cores:     ParseNumber(price.Product.Attributes.Vcpu, 1),
			GPUNumber: ParseNumber(price.Product.Attributes.Gpu, 0),
			DiskSize:  int(ParseStorage(price.Product.Attributes.Storage)),
			RAMSize:   float32(ParseMemory(price.Product.Attributes.Memory)),
		}

		templates = append(templates, tpl)
	}

	return templates, nil
}

// WaitHostReady waits an host achieve ready state
// hostParam can be an ID of host, or an instance of *resources.Host; any other type will panic
func (s *Stack) WaitHostReady(hostParam stacks.HostParameter, timeout time.Duration) (_ *abstract.HostCore, xerr fail.Error) {
	nullAhc := abstract.NewHostCore()
	if s == nil {
		return nullAhc, fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return nullAhc, xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s, %v)", hostRef, timeout).WithStopwatch().Entering().Exiting()
	defer fail.OnPanic(&xerr)
	defer fail.OnExitLogError(&xerr)

	retryErr := retry.WhileUnsuccessful(
		func() error {
			hostTmp, innerXErr := s.InspectHost(ahf)
			if innerXErr != nil {
				logrus.Warn(innerXErr)
				return innerXErr
			}

			ahf = hostTmp

			if hostTmp.CurrentState == hoststate.ERROR {
				innerXErr = retry.StopRetryError(fail.NewError(nil, "last state: %s", hostTmp.CurrentState), "error waiting for host in ready state")
				logrus.Warn(innerXErr)
				return innerXErr
			}

			if hostTmp.CurrentState != hoststate.STARTED {
				innerXErr = fail.NewError(nil, "not in ready state (current state: %s)", ahf.CurrentState.String())
				logrus.Warn(innerXErr)
				return innerXErr
			}
			return nil
		},
		temporal.GetDefaultDelay(),
		timeout,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry:
			return nullAhc, fail.ToError(retryErr.Cause())
		case *retry.ErrTimeout:
			return nullAhc, fail.Wrap(retryErr.Cause(), "timeout waiting to get host '%s' information after %v", ahf.GetID(), timeout)
		default:
			return nullAhc, retryErr
		}
	}
	return ahf.Core, nil
}

// CreateHost creates a host
func (s *Stack) CreateHost(request abstract.HostRequest) (ahf *abstract.HostFull, userData *userdata.Content, xerr fail.Error) {
	nullAhf := abstract.NewHostFull()
	nullUdc := userdata.NewContent()
	if s == nil {
		return nullAhf, nullUdc, fail.InvalidInstanceError()
	}
	if request.KeyPair == nil {
		return nullAhf, nullUdc, fail.InvalidParameterError("request.KeyPair", "cannot be nil")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%v)", request).WithStopwatch().Entering().Exiting()
	defer fail.OnPanic(&xerr)
	defer fail.OnExitLogError(&xerr)

	resourceName := request.ResourceName
	subnets := request.Subnets
	// hostMustHavePublicIP := request.PublicIP
	keyPairName := request.KeyPair.Name

	if subnets == nil || len(subnets) == 0 {
		return nullAhf, nullUdc, fail.InvalidRequestError("the host '%s' must be on at least one subnet (even if public)", resourceName)
	}

	// If no password is provided, create one
	if request.Password == "" {
		password, err := utils.GeneratePassword(16)
		if err != nil {
			return nullAhf, nullUdc, fail.Wrap(err, "failed to generate password")
		}
		request.Password = password
	}

	// The Default Network is the first of the provided list, by convention
	defaultSubnet, defaultSubnetID := func() (*abstract.Subnet, string) {
		if len(request.Subnets) == 0 {
			return nil, ""
		}
		return request.Subnets[0], request.Subnets[0].ID
	}()
	isGateway := request.IsGateway // && defaultNet != nil && defaultNet.Name != abstract.SingleHostNetworkName

	if defaultSubnet == nil && !request.PublicIP {
		return nullAhf, nullUdc, abstract.ResourceInvalidRequestError("host creation", "cannot create a host without public IP or without attached network")
	}

	// FIXME: AWS Remove logs
	if len(request.Subnets) == 1 {
		if s.Config.BuildSubnets {
			logrus.Warnf("We need either recalculate network segments here or pass the data through metadata")
			logrus.Warnf("Working network: %s", spew.Sdump(request.Subnets[0]))
		}
	} else {
		logrus.Warnf("Choosing between subnets: %s", spew.Sdump(request.Subnets))
	}

	// defaultSubnet := request.Networks[0]
	// defaultGateway := request.DefaultGateway
	// isGateway := defaultGateway == nil && defaultSubnet.Name != abstract.SingleHostNetworkName
	// defaultGatewayID := ""
	// defaultGatewayPrivateIP := ""
	// if defaultGateway != nil {
	//	xerr = defaultGateway.Properties.Inspect(hostproperty.NetworkV1, func(v data.Clonable) fail.Error {
	//		hostNetworkV1 := v.(*propertiesv1.HostSubnet)
	//		defaultGatewayPrivateIP = hostNetworkV1.IPv4Addresses[defaultNetworkID]
	//		defaultGatewayID = defaultGateway.ID
	//		return nil
	//	})
	//	if err != nil {
	//		return nil, userData, xerr
	//	}
	// }
	// if defaultGateway == nil && !hostMustHavePublicIP {
	//    return nil, userData, fail.InvalidRequestError("the host %s must have a gateway or be public", resourceName)
	// }

	// --- prepares data structures for Provider usage ---

	// Constructs userdata content
	userData = userdata.NewContent()
	xerr = userData.Prepare(*s.Config, request, defaultSubnet.CIDR, "")
	if xerr != nil {
		logrus.Debugf(strprocess.Capitalize(fmt.Sprintf("failed to prepare user data content: %+v", xerr)))
		return nullAhf, nullUdc, fail.Wrap(xerr, "failed to prepare user data content")
	}

	// Determine system disk size based on vcpus count
	template, xerr := s.InspectTemplate(request.TemplateID)
	if xerr != nil {
		return nullAhf, nullUdc, fail.Wrap(xerr, "failed to get host template '%s'", request.TemplateID)
	}

	rim, err := s.InspectImage(request.ImageID)
	if err != nil {
		return nullAhf, nullUdc, fail.Wrap(xerr, "failed to get image '%s'", request.ImageID)
	}

	logrus.Debugf("Selected template: '%s', '%s'", template.ID, template.Name)

	// Select usable availability zone, the first one in the list
	if s.AwsConfig.Zone == "" {
		azList, xerr := s.ListAvailabilityZones()
		if xerr != nil {
			return nullAhf, nullUdc, xerr
		}
		var az string
		for az = range azList {
			break
		}
		s.AwsConfig.Zone = az
		logrus.Debugf("Selected Availability Zone: '%s'", az)
	}

	// --- Initializes resources.Host ---

	ahf = abstract.NewHostFull()
	ahf.Core.PrivateKey = request.KeyPair.PrivateKey // Add PrivateKey to ahf definition
	ahf.Core.Password = request.Password

	// TODO: adapt to abstract.HostFull.HostSubnet
	ahf.Subnet.DefaultSubnetID = defaultSubnetID
	ahf.Subnet.IsGateway = isGateway

	// Adds Host property SizingV1
	ahf.Sizing = converters.HostTemplateToHostEffectiveSizing(*template)

	// Sets provider parameters to create ahf
	userDataPhase1, xerr := userData.Generate("phase1")
	if err != nil {
		return nullAhf, nullUdc, xerr
	}

	vpcnet, xerr := s.InspectNetworkByName(s.AwsConfig.NetworkName)
	if err != nil {
		return nullAhf, nullUdc, xerr
	}

	// --- query provider for ahf creation ---

	logrus.Debugf("requesting host resource creation...")
	var desistError error

	sgRules := stacks.DefaultTCPRules()
	sgRules = append(sgRules, stacks.DefaultUDPRules()...)
	sgRules = append(sgRules, stacks.DefaultICMPRules()...)

	// Retry creation until success, for 10 minutes
	xerr = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			var asg *abstract.SecurityGroup
			sgName := request.ResourceName + "-default-sg"
			if ok, innerErr := hasSecurityGroup(s.EC2Service, vpcnet.ID, sgName); innerErr == nil {
				if !ok {
					logrus.Debug("Security group not found")
					asg, innerErr = s.CreateSecurityGroup(vpcnet.ID, sgName, fmt.Sprintf("Default Security Group for host %s", request.ResourceName), nil)
					if innerErr != nil {
						desistError = innerErr
						return nil
					}
				}
			} else {
				logrus.Debugf("Error happened: %v", innerErr)
				desistError = innerErr
				return nil
			}

			//sgID, err := getSecurityGroupID(s.EC2Service, vpcnet.ID, request.ResourceName)
			//if err != nil {
			//	desistError = err
			//	return nil
			//}
			//
			var server *abstract.HostCore

			trick := request.Disposable
			if trick {
				netID := defaultSubnet.ID
				//if isGateway {
				//	netID = defaultSubnet.ID
				//} else {
				//	netID = defaultSubnet.ID
				//}

				server, xerr = s.buildAwsSpotMachine(keyPairName, request.ResourceName, rim.ID, s.AwsConfig.Zone, netID, string(userDataPhase1), isGateway, *template, asg.ID)
			} else {
				netID := defaultSubnet.ID
				//if s.Config.BuildSubnets && len(defaultSubnet.Subnetworks) >= 2 {
				//	if isGateway {
				//		netID = defaultSubnet.Subnetworks[0].ID
				//	} else {
				//		netID = defaultSubnet.Subnetworks[1].ID
				//	}
				//}

				server, err = s.buildAwsMachine(keyPairName, request.ResourceName, rim.ID, s.AwsConfig.Zone, netID, string(userDataPhase1), isGateway, *template, asg.ID)
			}
			if err != nil {
				logrus.Warnf("error creating ahf: %+v", err)

				if server != nil {
					killErr := s.DeleteHost(server.ID)
					if killErr != nil {
						return fail.Wrap(err, killErr.Error())
					}
				}

				if isAWSErr(err) {
					desistError = err
					return nil
				}

				return err
			}

			if server == nil {
				return fail.NewError(nil, "failed to create server")
			}

			ahf.Core.ID = server.ID
			ahf.Core.Name = server.Name

			// Wait until Host is ready, not just until the build is started
			_, err = s.WaitHostReady(ahf, temporal.GetLongOperationTimeout())
			if err != nil {
				killErr := s.DeleteHost(ahf.Core.ID)
				if killErr != nil {
					return fail.Wrap(err, killErr.Error())
				}
				return err
			}

			return nil
		},
		temporal.GetLongOperationTimeout(),
	)
	if err != nil {
		return nullAhf, nullUdc, fail.Wrap(err, "Error creating ahf: timeout")
	}
	if desistError != nil {
		return nullAhf, nullUdc, fail.ForbiddenError(fmt.Sprintf("Error creating ahf: %s", desistError.Error()))
	}

	logrus.Debugf("ahf resource created.")

	// Starting from here, delete host if exiting with error
	defer func() {
		if err != nil { // FIXME: Handle error groups
			logrus.Infof("Cleanup, deleting host '%s'", ahf.Core.Name)
			derr := s.DeleteHost(ahf.Core.ID)
			if derr != nil {
				logrus.Warnf("Error deleting ahf: %v", derr)
			}
		}
	}()

	if ahf.IsNull() {
		return nullAhf, nullUdc, fail.InconsistentError("unexpected nil ahf")
	}

	if !ahf.OK() {
		logrus.Warnf("Missing data in ahf: %v", ahf)
	}

	return ahf, userData, nil

}

// Returns true if the error is of type awserr.Error
func isSpecificAWSErr(err error, code string, message string) bool {
	if err, ok := err.(awserr.Error); ok {
		logrus.Warnf("Received AWS error code: %s", err.Code())
		return err.Code() == code && strings.Contains(err.Message(), message)
	}
	return false
}

/*
Returns true if the error matches all these conditions:
- err if of type awserr.Error
- Error.Code() matches code
- Error.Message() contains message
*/
func isAWSErr(err error) bool {
	if err, ok := err.(awserr.Error); ok {
		logrus.Warnf("Received AWS error code: %s", err.Code())
		return true
	}

	return false
}

func hasSecurityGroup(EC2Service *ec2.EC2, vpcID string, name string) (bool, error) {
	dgo, err := EC2Service.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{{
			Name:   aws.String("group-name"),
			Values: []*string{aws.String(name)},
		}},
	})
	if err != nil {
		return false, err
	}

	for _, sg := range dgo.SecurityGroups {
		if aws.StringValue(sg.VpcId) == vpcID {
			return true, nil
		}
	}

	return false, nil
}

//func getSecurityGroupID(EC2Service *ec2.EC2, vpcID string, name string) (string, error) {
//	dgo, err := EC2Service.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
//		Filters: []*ec2.Filter{{
//			Name:   aws.String("group-name"),
//			Values: []*string{aws.String(name)},
//		}},
//	})
//	if err != nil {
//		return "", err
//	}
//
//	for _, sg := range dgo.SecurityGroups {
//		if aws.StringValue(sg.VpcId) == vpcID {
//			return aws.StringValue(sg.GroupId), nil
//		}
//	}
//
//	return "", fail.NotFoundError(fmt.Sprintf("Security group %s not found", name))
//}
//
//func createSecurityGroup(EC2Service *ec2.EC2, vpcID string, name string) error {
//	logrus.Warnf("Creating security group for vpc %s with name %s", vpcID, name)
//
//	// Create the security group with the VPC, name and description.
//	createRes, err := EC2Service.CreateSecurityGroup(&ec2.CreateSecurityGroupInput{
//		Description: aws.String(fmt.Sprintf("Default group cfg for vpc %s", vpcID)),
//		GroupName:   aws.String(name),
//		VpcId:       aws.String(vpcID),
//	})
//	if err != nil {
//		if aerr, ok := err.(awserr.Error); ok {
//			switch aerr.Code() {
//			case "InvalidVpcID.NotFound":
//				return fail.Wrap(err, "unable to find VPC with ID %q", vpcID)
//			case "InvalidGroup.Duplicate":
//				return fail.Wrap(err, "security group %q already exists", name)
//			}
//		}
//		return fail.Wrap(err, "unable to create security group %q", name)
//	}
//	fmt.Printf("Created security group %s with VPC %s.\n",
//		aws.StringValue(createRes.GroupId), vpcID)
//
//	var ports []portDef
//
//	// Add common ports
//	ports = append(ports, portDef{"tcp", 22, 22})
//	ports = append(ports, portDef{"tcp", 80, 80})
//	ports = append(ports, portDef{"tcp", 443, 443})
//
//	// Guacamole ports
//	ports = append(ports, portDef{"tcp", 8080, 8080})
//	ports = append(ports, portDef{"tcp", 8009, 8009})
//	ports = append(ports, portDef{"tcp", 9009, 9009})
//	ports = append(ports, portDef{"tcp", 3389, 3389})
//	ports = append(ports, portDef{"tcp", 5900, 5900})
//	ports = append(ports, portDef{"tcp", 63011, 63011})
//
//	// Add time server
//	ports = append(ports, portDef{"udp", 123, 123})
//
//	// Add kubernetes see https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/#check-required-ports
//	ports = append(ports, portDef{"tcp", 6443, 6443})
//	ports = append(ports, portDef{"tcp", 2379, 2380})
//	ports = append(ports, portDef{"tcp", 10250, 10250})
//	ports = append(ports, portDef{"tcp", 10251, 10251})
//	ports = append(ports, portDef{"tcp", 10252, 10252})
//	ports = append(ports, portDef{"tcp", 10255, 10255})
//	ports = append(ports, portDef{"tcp", 30000, 32767})
//
//	// Add docker swarm ports
//	ports = append(ports, portDef{"tcp", 2376, 2376})
//	ports = append(ports, portDef{"tcp", 2377, 2377})
//	ports = append(ports, portDef{"tcp", 7946, 7946})
//	ports = append(ports, portDef{"udp", 7946, 7946})
//	ports = append(ports, portDef{"udp", 4789, 4789})
//
//	// ping
//	ports = append(ports, portDef{"icmp", -1, -1})
//
//	var permissions []*ec2.IpPermission
//	for _, item := range ports {
//		permissions = append(permissions, (&ec2.IpPermission{}).
//			SetIpProtocol(item.protocol).
//			SetFromPort(item.fromPort).
//			SetToPort(item.toPort).
//			SetIpRanges([]*ec2.IpRange{
//				{CidrIp: aws.String("0.0.0.0/0")},
//			}))
//	}
//
//	// Add permissions to the security group
//	_, err = EC2Service.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
//		GroupId:       createRes.GroupId,
//		IpPermissions: permissions,
//	})
//	if err != nil {
//		return fail.Wrap(err, "unable to set security group %q ingress", name)
//	}
//
//	return nil
//}

func (s Stack) buildAwsSpotMachine(
	keypairName string,
	name string,
	imageId string,
	zone string,
	netID string,
	data string,
	isGateway bool,
	template abstract.HostTemplate,
	sgID string,
) (*abstract.HostCore, fail.Error) {

	ni := &ec2.InstanceNetworkInterfaceSpecification{
		DeviceIndex:              aws.Int64(int64(0)),
		SubnetId:                 aws.String(netID),
		AssociatePublicIpAddress: aws.Bool(isGateway),
		Groups:                   []*string{aws.String(sgID)},
	}

	dspho, err := s.EC2Service.DescribeSpotPriceHistory(&ec2.DescribeSpotPriceHistoryInput{
		AvailabilityZone:    aws.String(zone),
		InstanceTypes:       []*string{aws.String(template.ID)},
		ProductDescriptions: []*string{aws.String("Linux/UNIX")},
	})
	if err != nil {
		return nil, normalizeError(err)
	}

	lastPrice := dspho.SpotPriceHistory[len(dspho.SpotPriceHistory)-1]
	logrus.Warnf("Last price detected %s", aws.StringValue(lastPrice.SpotPrice))

	input := &ec2.RequestSpotInstancesInput{
		InstanceCount: aws.Int64(1),
		LaunchSpecification: &ec2.RequestSpotLaunchSpecification{
			ImageId:           aws.String(imageId),
			InstanceType:      aws.String(template.ID),
			KeyName:           aws.String(keypairName),
			NetworkInterfaces: []*ec2.InstanceNetworkInterfaceSpecification{ni},
			Placement: &ec2.SpotPlacement{
				AvailabilityZone: aws.String(zone),
			},
			UserData: aws.String(base64.StdEncoding.EncodeToString([]byte(data))),
		},
		SpotPrice: lastPrice.SpotPrice, // FIXME: Round up
		Type:      aws.String("one-time"),
	}

	result, err := s.EC2Service.RequestSpotInstances(input)
	if err != nil {
		return nil, normalizeError(err)
	}

	instance := result.SpotInstanceRequests[0]

	// FIXME: Listen to result.SpotInstanceRequests[0].State

	host := abstract.HostCore{
		ID:   aws.StringValue(instance.InstanceId),
		Name: name,
	}
	return &host, nil
}

func (s Stack) buildAwsMachine(
	keypairName string,
	name string,
	imageId string,
	zone string,
	netID string,
	data string,
	isGateway bool,
	template abstract.HostTemplate,
	sgID string,
) (*abstract.HostCore, fail.Error) {

	//logrus.Warnf("Using %s as subnetwork, looking for group %s", netID, sgID)

	ni := &ec2.InstanceNetworkInterfaceSpecification{
		DeviceIndex:              aws.Int64(int64(0)),
		SubnetId:                 aws.String(netID),
		AssociatePublicIpAddress: aws.Bool(isGateway),
		Groups:                   []*string{aws.String(sgID)},
	}

	// Run instance
	out, err := s.EC2Service.RunInstances(&ec2.RunInstancesInput{
		ImageId:      aws.String(imageId),
		InstanceType: aws.String(template.ID),
		KeyName:      aws.String(keypairName),
		MaxCount:     aws.Int64(1),
		MinCount:     aws.Int64(1),
		Placement: &ec2.Placement{
			AvailabilityZone: aws.String(zone),
		},
		NetworkInterfaces: []*ec2.InstanceNetworkInterfaceSpecification{ni},
		TagSpecifications: []*ec2.TagSpecification{
			{
				ResourceType: aws.String("instance"),
				Tags: []*ec2.Tag{
					{
						Key:   aws.String("Name"),
						Value: aws.String(name),
					},
				},
			},
		},
		UserData: aws.String(base64.StdEncoding.EncodeToString([]byte(data))),
	})
	if err != nil {
		return nil, normalizeError(err)
	}

	_, err = s.EC2Service.ModifyInstanceAttribute(&ec2.ModifyInstanceAttributeInput{
		InstanceId:      out.Instances[0].InstanceId,
		SourceDestCheck: &ec2.AttributeBooleanValue{Value: aws.Bool(false)},
	})
	if err != nil {
		return nil, normalizeError(err)
	}

	instance := out.Instances[0]

	hostCore := abstract.HostCore{
		ID:   aws.StringValue(instance.InstanceId),
		Name: name,
	}
	return &hostCore, nil
}

// InspectHost loads information of a host from AWS
func (s *Stack) InspectHost(hostParam stacks.HostParameter) (ahf *abstract.HostFull, xerr fail.Error) {
	ahf = abstract.NewHostFull()
	if s == nil {
		return ahf, fail.InvalidInstanceError()
	}

	var hostRef string
	ahf, hostRef, xerr = stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return ahf, xerr
	}
	if utils.IsEmpty(ahf) {
		return nil, abstract.ResourceNotFoundError("host", hostRef)
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()
	defer fail.OnPanic(&xerr)
	defer fail.OnExitLogError(&xerr)

	awsHost, err := s.EC2Service.DescribeInstances(&ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("instance-id"),
				Values: []*string{aws.String(hostRef)},
			},
		},
	})
	if err != nil {
		return nil, fail.ToError(err)
	}

	if len(awsHost.Reservations) == 0 {
		awsHost, err = s.EC2Service.DescribeInstances(&ec2.DescribeInstancesInput{
			Filters: []*ec2.Filter{
				{
					Name: aws.String("tag:Name"),
					Values: []*string{
						aws.String(hostRef),
					},
				},
			},
		})
		if err != nil {
			return nil, fail.ToError(err)
		}
	}

	if len(awsHost.Reservations) == 0 {
		return nil, fail.NotFoundError(fmt.Sprintf("host %s not found", hostRef))
	}

	instanceName := ""
	instanceType := ""

	for _, r := range awsHost.Reservations {
		for _, i := range r.Instances {
			ahf.Core.LastState, xerr = toHostState(i.State)
			if err != nil {
				return nil, xerr
			}

			for _, tag := range i.Tags {
				if tag != nil {
					if aws.StringValue(tag.Key) == "Name" || aws.StringValue(tag.Key) == "tag:Name" {
						if aws.StringValue(tag.Value) != "" {
							instanceName = aws.StringValue(tag.Value)
						}
					}
				}
			}

			if aws.StringValue(i.InstanceType) != "" {
				instanceType = aws.StringValue(i.InstanceType)
				break
			}
		}
	}

	if instanceType == "" {
		return nil, fail.NewError(nil, "error recovering instance type of %s", hostRef)
	}

	var subnets []IPInSubnet

	for _, r := range awsHost.Reservations {
		for _, i := range r.Instances {
			for _, ni := range i.NetworkInterfaces {
				newSubnet := IPInSubnet{
					Name: getTagOfSubnet(s.EC2Service, ni.SubnetId, "Name"),
					ID:   aws.StringValue(ni.SubnetId),
					IP:   aws.StringValue(ni.PrivateIpAddress),
				}

				if ni.Association != nil {
					if ni.Association.PublicIp != nil {
						newSubnet.PublicIP = aws.StringValue(ni.Association.PublicIp)
					}
				}

				subnets = append(subnets, newSubnet)
			}
		}
	}

	ip4bynetid := make(map[string]string)
	subnetnamebyid := make(map[string]string)
	subnetidbyname := make(map[string]string)

	ipv4 := ""
	for _, rn := range subnets {
		ip4bynetid[rn.ID] = rn.IP
		subnetnamebyid[rn.ID] = rn.Name
		subnetidbyname[rn.Name] = rn.ID
		if rn.PublicIP != "" {
			ipv4 = rn.PublicIP
		}
	}

	ahf.Subnet.IPv4Addresses = ip4bynetid
	ahf.Subnet.IPv6Addresses = make(map[string]string)
	ahf.Subnet.SubnetsByID = subnetnamebyid
	ahf.Subnet.SubnetsByName = subnetidbyname
	if ahf.Subnet.PublicIPv4 == "" {
		ahf.Subnet.PublicIPv4 = ipv4
	}

	sizing := fromMachineTypeToHostEffectiveSizing(s, instanceType)

	ahf.Sizing.Cores = sizing.Cores
	ahf.Sizing.RAMSize = sizing.RAMSize
	ahf.Sizing.DiskSize = sizing.DiskSize

	ahf.Core.Name = instanceName

	if !ahf.OK() {
		logrus.Warnf("[TRACE] Unexpected host status: %s", spew.Sdump(ahf))
	}

	return ahf, nil
}

func fromMachineTypeToHostEffectiveSizing(stack *Stack, machineType string) abstract.HostEffectiveSizing {
	nullSizing := abstract.HostEffectiveSizing{}

	templates, xerr := stack.ListTemplates()
	if xerr != nil {
		return nullSizing
	}

	for _, template := range templates {
		if template.Name == machineType {
			hs := abstract.HostEffectiveSizing{
				Cores:     template.Cores,
				CPUFreq:   template.CPUFreq,
				DiskSize:  template.DiskSize,
				RAMSize:   template.RAMSize,
				GPUNumber: template.GPUNumber,
				GPUType:   template.GPUType,
			}
			return hs
		}
	}
	return nullSizing
}

func getTagOfSubnet(EC2Service *ec2.EC2, SubnetId *string, s string) string {
	sno, err := EC2Service.DescribeSubnets(&ec2.DescribeSubnetsInput{
		SubnetIds: []*string{SubnetId},
	})
	if err != nil {
		return aws.StringValue(SubnetId)
	}

	if len(sno.Subnets) > 0 {
		first := sno.Subnets[0]
		for _, tag := range first.Tags {
			if aws.StringValue(tag.Key) == s {
				return aws.StringValue(tag.Value)
			}
		}
	}

	return aws.StringValue(SubnetId)
}

// InspectHostByName returns host information by its name
func (s *Stack) InspectHostByName(name string) (_ *abstract.HostCore, xerr fail.Error) {
	nullAhc := abstract.NewHostCore()
	if s == nil {
		return nullAhc, fail.InvalidInstanceError()
	}
	if name == "" {
		return nullAhc, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "('%s')", name).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	hosts, err := s.ListHosts(false)
	if err != nil {
		return nullAhc, err
	}

	for _, ahf := range hosts {
		if ahf.GetName() == name {
			return ahf.Core, nil
		}
	}

	return nil, abstract.ResourceNotFoundError("host", name)
}

// GetHostState returns the current state of the host
func (s *Stack) GetHostState(hostParam stacks.HostParameter) (_ hoststate.Enum, xerr fail.Error) {
	if s == nil {
		return hoststate.ERROR, fail.InvalidInstanceError()
	}

	host, xerr := s.InspectHost(hostParam)
	if xerr != nil {
		return hoststate.ERROR, xerr
	}

	return host.Core.LastState, nil
}

// ListHosts returns a list of hosts
func (s *Stack) ListHosts(details bool) (hosts abstract.HostList, xerr fail.Error) {
	nullList := abstract.HostList{}
	if s == nil {
		return nullList, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(details=%v)", details).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	dio, err := s.EC2Service.DescribeInstances(&ec2.DescribeInstancesInput{})
	if err != nil {
		return nullList, fail.ToError(err)
	}

	hosts = abstract.HostList{}
	for _, reservation := range dio.Reservations {
		if reservation != nil {
			for _, instance := range reservation.Instances {
				if instance != nil {
					state, _ := toHostState(instance.State)
					name := ""

					for _, tag := range instance.Tags {
						if aws.StringValue(tag.Key) == "Name" {
							if aws.StringValue(tag.Value) != "" {
								name = aws.StringValue(tag.Value)
							}
						}
					}

					ahf := abstract.NewHostFull()
					ahf.Core.ID = aws.StringValue(instance.InstanceId)
					ahf.Core.Name = name
					ahf.Core.LastState = state
					if details {
						ahf, xerr = s.InspectHost(ahf)
						if xerr != nil {
							return nullList, xerr
						}
					}
					hosts = append(hosts, ahf)
				}
			}
		}
	}

	return hosts, nil
}

// DeleteHost deletes a host
func (s *Stack) DeleteHost(hostParam stacks.HostParameter) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	ips, err := s.EC2Service.DescribeAddresses(&ec2.DescribeAddressesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("instance-id"),
				Values: []*string{aws.String(ahf.GetID())},
			},
		},
	})
	if err != nil {
		if ips != nil {
			for _, ip := range ips.Addresses {
				_, _ = s.EC2Service.ReleaseAddress(&ec2.ReleaseAddressInput{
					AllocationId: ip.AllocationId,
				})
			}
		}
	}

	dio, err := s.EC2Service.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: []*string{aws.String(ahf.GetID())},
	})
	if err != nil {
		return fail.ToError(err)
	}

	// Get keypair and security group
	var keyPairName string
	var secGroupId string

	var attachedVolumes []string

	if dio != nil {
		if len(dio.Reservations) > 0 {
			res := dio.Reservations[0]
			if len(res.Instances) > 0 {
				inst := res.Instances[0]

				// register attached volumes
				for _, attVol := range inst.BlockDeviceMappings {
					if attVol != nil {
						if attVol.Ebs != nil {
							if attVol.Ebs.VolumeId != nil {
								volume := aws.StringValue(attVol.Ebs.VolumeId)
								if volume != "" {
									attachedVolumes = append(attachedVolumes, volume)
								}
							}
						}
					}
				}

				if inst != nil {
					keyPairName = aws.StringValue(inst.KeyName)
					if len(inst.SecurityGroups) > 0 {
						sg := inst.SecurityGroups[0]
						secGroupId = aws.StringValue(sg.GroupId)
					}
				}
			}
		}
	}

	// Terminate instance
	_, err = s.EC2Service.TerminateInstances(&ec2.TerminateInstancesInput{
		InstanceIds: []*string{aws.String(ahf.GetID())},
	})
	if err != nil {
		return fail.ToError(err)
	}

	retryErr := retry.WhileUnsuccessful(
		func() error {
			hostTmp, err := s.InspectHost(ahf)
			if err != nil {
				return err
			}

			if !(hostTmp.Core.LastState == hoststate.STOPPED || hostTmp.Core.LastState == hoststate.TERMINATED) {
				return fail.NewError(err, "not in stopped or terminated state (current state: %s)", hostTmp.Core.LastState.String())
			}
			return nil
		},
		temporal.GetDefaultDelay(),
		temporal.GetHostCleanupTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrTimeout:
			return fail.Wrap(retryErr.Cause(), "timeout waiting to get host '%s' information after %v", ahf.GetID(), temporal.GetHostCleanupTimeout())
		default:
			return retryErr
		}
	}

	// Remove volumes if there, mark errors as warnings
	for _, volume := range attachedVolumes {
		_, err = s.EC2Service.DeleteVolume(&ec2.DeleteVolumeInput{
			VolumeId: aws.String(volume),
		})
		if err != nil {
			logrus.Warnf("problem cleaning up, deleting volume %s", volume)
		}
	}

	// Remove security group
	if secGroupId != "" {
		_, err = s.EC2Service.DeleteSecurityGroup(&ec2.DeleteSecurityGroupInput{
			GroupId: aws.String(secGroupId),
		})
		if err != nil {
			return fail.Wrap(err, "error deleting security group")
		}
	} else {
		logrus.Warnf("security group %s for host '%s' not found", secGroupId, hostRef)
	}

	// Remove keypair
	if keyPairName != "" {
		_, err = s.EC2Service.DeleteKeyPair(&ec2.DeleteKeyPairInput{
			KeyName: aws.String(keyPairName),
		})
		if err != nil {
			return fail.Wrap(err, "error deleting keypair")
		}
	} else {
		logrus.Warnf("keypair '%s' for host '%s' not found", keyPairName, ahf.GetID())
	}

	return nil
}

// StopHost stops a running host
func (s *Stack) StopHost(hostParam stacks.HostParameter) (xerr fail.Error) {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	_, err := s.EC2Service.StopInstances(&ec2.StopInstancesInput{
		Force:       aws.Bool(true),
		InstanceIds: []*string{aws.String(ahf.Core.ID)},
	})
	if err != nil {
		return fail.ToError(err)
	}

	retryErr := retry.WhileUnsuccessful(
		func() error {
			hostTmp, err := s.InspectHost(ahf.Core.ID)
			if err != nil {
				return err
			}

			if !(hostTmp.Core.LastState == hoststate.STOPPED || hostTmp.Core.LastState == hoststate.TERMINATED) {
				return fail.NewError("not in stopped or terminated state (current state: %s)", hostTmp.Core.LastState.String())
			}
			return nil
		},
		temporal.GetDefaultDelay(),
		temporal.GetHostCleanupTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrTimeout:
			return fail.Wrap(retryErr.Cause(), "timeout waiting to get host '%s' information after %v", hostRef, temporal.GetHostCleanupTimeout())
		}
		return retryErr
	}

	return nil
}

// StartHost starts a stopped host
func (s *Stack) StartHost(hostParam stacks.HostParameter) (xerr fail.Error) {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	_, err := s.EC2Service.StartInstances(&ec2.StartInstancesInput{
		InstanceIds: []*string{aws.String(ahf.Core.ID)},
	})
	if err != nil {
		return normalizeError(err)
	}

	retryErr := retry.WhileUnsuccessful(
		func() error {
			hostTmp, err := s.InspectHost(ahf.Core.ID)
			if err != nil {
				return err
			}

			if hostTmp.Core.LastState != hoststate.STARTED {
				return fail.NewError("not in started state (current state: %s)", hostTmp.Core.LastState.String())
			}
			return nil
		},
		temporal.GetDefaultDelay(),
		temporal.GetHostCleanupTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrTimeout:
			return fail.Wrap(retryErr.Cause(), "timeout waiting to get information of host '%s' after %v", hostRef, temporal.GetHostCleanupTimeout())
		default:
			return retryErr
		}
	}

	return nil
}

// RebootHost stops then starts a host
func (s *Stack) RebootHost(hostParam stacks.HostParameter) (xerr fail.Error) {
	if s == nil {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	_, err := s.EC2Service.RebootInstances(&ec2.RebootInstancesInput{
		InstanceIds: []*string{aws.String(ahf.Core.ID)},
	})
	if err != nil {
		return normalizeError(err)
	}

	retryErr := retry.WhileUnsuccessful(
		func() error {
			hostTmp, innerErr := s.InspectHost(ahf)
			if innerErr != nil {
				return innerErr
			}

			if hostTmp.Core.LastState != hoststate.STARTED {
				return fail.NewError("not in started state (current state: %s)", hostTmp.Core.LastState.String())
			}
			return nil
		},
		temporal.GetDefaultDelay(),
		2*temporal.GetHostCleanupTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrTimeout:
			return fail.NewError("timeout waiting to get host '%s' information after %v", hostRef, temporal.GetHostCleanupTimeout())
		default:
			return retryErr
		}
	}

	return nil
}

// ResizeHost changes the sizing of an existing host
func (s *Stack) ResizeHost(hostParam stacks.HostParameter, request abstract.HostSizingRequirements) (*abstract.HostFull, fail.Error) {
	return nil, fail.NotImplementedError("ResizeHost() not implemented yet") // FIXME: Technical debt
}

// BindSecurityGroupToHost ...
func (s *Stack) BindSecurityGroupToHost(hostParam stacks.HostParameter, sgParam stacks.SecurityGroupParameter) fail.Error {
	return fail.NotImplementedError("not yet implemented")
}

// UnbindSecurityGroupFromHost ...
func (s *Stack) UnbindSecurityGroupFromHost(hostParam stacks.HostParameter, sgParam stacks.SecurityGroupParameter) fail.Error {
	return fail.NotImplementedError("not yet implemented")
}
