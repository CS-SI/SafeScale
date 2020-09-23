/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/pricing"

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/properties"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/iaas/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

type portDef struct {
	protocol string
	fromPort int64
	toPort   int64
}

func (s *Stack) CreateKeyPair(name string) (*resources.KeyPair, error) {
	keypair, err := resources.NewKeyPair(name)
	if err != nil {
		return nil, err
	}
	_, err = s.EC2Service.ImportKeyPair(
		&ec2.ImportKeyPairInput{
			KeyName:           aws.String(name),
			PublicKeyMaterial: []byte(keypair.PublicKey),
		},
	)
	if err != nil {
		return nil, err
	}

	err = s.ImportKeyPair(keypair)
	if err != nil {
		return nil, err
	}

	return keypair, nil
}

// ImportKeyPair imports an existing resources.KeyPair inside the provider (not in the interface yet, but will come soon)
func (s *Stack) ImportKeyPair(keypair *resources.KeyPair) error {
	if keypair == nil {
		return scerr.InvalidParameterError("keypair", "cannot be nil")
	}
	_, err := s.EC2Service.ImportKeyPair(
		&ec2.ImportKeyPairInput{
			KeyName:           aws.String(keypair.Name),
			PublicKeyMaterial: []byte(keypair.PublicKey),
		},
	)
	return err
}

func (s *Stack) GetKeyPair(id string) (*resources.KeyPair, error) {
	out, err := s.EC2Service.DescribeKeyPairs(
		&ec2.DescribeKeyPairsInput{
			KeyNames: []*string{aws.String(id)},
		},
	)
	if err != nil {
		return nil, err
	}
	if len(out.KeyPairs) == 0 {
		return nil, scerr.Errorf(fmt.Sprintf("no keypairs found"), nil)
	}

	kp := out.KeyPairs[0]
	return &resources.KeyPair{
		ID:         aws.StringValue(kp.KeyName),
		Name:       aws.StringValue(kp.KeyName),
		PrivateKey: "",
		PublicKey:  aws.StringValue(kp.KeyFingerprint),
	}, nil

}

func (s *Stack) ListKeyPairs() ([]resources.KeyPair, error) {
	out, err := s.EC2Service.DescribeKeyPairs(&ec2.DescribeKeyPairsInput{})
	if err != nil {
		return nil, err
	}
	var keys []resources.KeyPair
	for _, kp := range out.KeyPairs {
		keys = append(
			keys, resources.KeyPair{
				ID:         aws.StringValue(kp.KeyName),
				Name:       aws.StringValue(kp.KeyName),
				PrivateKey: "",
				PublicKey:  aws.StringValue(kp.KeyFingerprint),
			},
		)

	}
	return keys, nil
}

func (s *Stack) DeleteKeyPair(id string) error {
	_, err := s.EC2Service.DeleteKeyPair(
		&ec2.DeleteKeyPairInput{
			KeyName: aws.String(id),
		},
	)

	return err
}

func (s *Stack) ListAvailabilityZones() (map[string]bool, error) {
	zones := make(map[string]bool)

	ro, err := s.EC2Service.DescribeAvailabilityZones(&ec2.DescribeAvailabilityZonesInput{})
	if err != nil {
		return zones, err
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

func (s *Stack) ListRegions() ([]string, error) {
	var regions []string

	ro, err := s.EC2Service.DescribeRegions(&ec2.DescribeRegionsInput{})
	if err != nil {
		return regions, err
	}
	if ro != nil {
		for _, region := range ro.Regions {
			regions = append(regions, aws.StringValue(region.RegionName))
		}
	}

	return regions, nil
}

func (s *Stack) GetImage(id string) (*resources.Image, error) {
	imagesList, err := s.ListImages()
	if err != nil {
		return nil, err
	}
	for _, res := range imagesList {
		if res.ID == id {
			return &res, nil
		}
	}

	return nil, resources.ResourceNotFoundError("Image", id)
}

func (s *Stack) GetTemplate(id string) (*resources.HostTemplate, error) {
	template := resources.HostTemplate{}

	prods, err := s.PricingService.GetProducts(
		&pricing.GetProductsInput{
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
		},
	)
	if err != nil {
		return &template, err
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

		tpl := resources.HostTemplate{
			ID:        price.Product.Attributes.InstanceType,
			Name:      price.Product.Attributes.InstanceType,
			Cores:     ParseNumber(price.Product.Attributes.Vcpu, 1),
			GPUNumber: ParseNumber(price.Product.Attributes.Gpu, 0),
			DiskSize:  int(ParseStorage(price.Product.Attributes.Storage)),
			RAMSize:   float32(ParseMemory(price.Product.Attributes.Memory)),
		}

		template = tpl
		break
	}

	return &template, nil
}

func createFilters() []*ec2.Filter {
	filters := []*ec2.Filter{
		&ec2.Filter{
			Name:   aws.String("state"),
			Values: []*string{aws.String("available")},
		},
		&ec2.Filter{
			Name:   aws.String("architecture"),
			Values: []*string{aws.String("x86_64")},
		},
		&ec2.Filter{
			Name:   aws.String("virtualization-type"),
			Values: []*string{aws.String("hvm")},
		},
		&ec2.Filter{
			Name:   aws.String("root-device-type"),
			Values: []*string{aws.String("ebs")},
		},
		&ec2.Filter{
			Name:   aws.String("ena-support"),
			Values: []*string{aws.String("true")},
		},
	}

	// FIXME: AWS CentOS AND Others
	owners := []*string{
		aws.String("099720109477"), // Ubuntu
		aws.String("013116697141"), // Fedora
		aws.String("379101102735"), // Debian
		aws.String("125523088429"), // CentOS 8
		aws.String("161831738826"), // Centos 7 with ENA
		aws.String("057448758665"), // Centos 7
		aws.String("679593333241"), // Centos 6 AND Others
		aws.String("595879546273"), // CoreOS
	}
	filters = append(
		filters, &ec2.Filter{
			Name:   aws.String("owner-id"),
			Values: owners,
		},
	)
	return filters
}

func (s *Stack) ListImages() ([]resources.Image, error) {
	var images []resources.Image

	filters := []*ec2.Filter{
		&ec2.Filter{
			Name:   aws.String("architecture"),
			Values: []*string{aws.String("x86_64")},
		},
		&ec2.Filter{
			Name:   aws.String("state"),
			Values: []*string{aws.String("available")},
		},
	}

	// Added filtering by owner-id
	filters = append(filters, createFilters()...)

	iout, err := s.EC2Service.DescribeImages(
		&ec2.DescribeImagesInput{
			Filters: filters,
		},
	)
	if err != nil {
		return images, err
	}
	if iout != nil {
		for _, image := range iout.Images {
			if image != nil {
				if !aws.BoolValue(image.EnaSupport) {
					logrus.Warnf("ENA filtering does NOT actually work !")
				}

				nextImage := resources.Image{
					ID:          aws.StringValue(image.ImageId),
					Name:        aws.StringValue(image.Name),
					Description: aws.StringValue(image.Description),
					StorageType: aws.StringValue(image.RootDeviceType),
					DiskSize:    0,
				}

				if len(image.BlockDeviceMappings) > 0 {
					if image.BlockDeviceMappings[0].Ebs != nil {
						if image.BlockDeviceMappings[0].Ebs.VolumeSize != nil {
							nextImage.DiskSize = aws.Int64Value(image.BlockDeviceMappings[0].Ebs.VolumeSize)
						}
					}
				}

				images = append(images, nextImage)
			}
		}
	}

	return images, nil
}

func (s *Stack) ListTemplates() ([]resources.HostTemplate, error) {
	var templates []resources.HostTemplate

	prods, err := s.PricingService.GetProducts(
		&pricing.GetProductsInput{
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
		},
	)
	if err != nil {
		return templates, err
	}

	hostTemplates := make(map[string]resources.HostTemplate)

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

		tpl := resources.HostTemplate{
			ID:        price.Product.Attributes.InstanceType,
			Name:      price.Product.Attributes.InstanceType,
			Cores:     ParseNumber(price.Product.Attributes.Vcpu, 1),
			GPUNumber: ParseNumber(price.Product.Attributes.Gpu, 0),
			DiskSize:  int(ParseStorage(price.Product.Attributes.Storage)),
			RAMSize:   float32(ParseMemory(price.Product.Attributes.Memory)),
		}

		hostTemplates[price.Product.Attributes.InstanceType] = tpl
	}

	for _, v := range hostTemplates {
		templates = append(templates, v)
	}

	return templates, nil
}

// WaitHostReady waits an host achieve ready state
// hostParam can be an ID of host, or an instance of *resources.Host; any other type will panic
func (s *Stack) WaitHostReady(hostParam interface{}, timeout time.Duration) (*resources.Host, error) {
	var (
		host *resources.Host
	)
	switch hostParam := hostParam.(type) {
	case string:
		host = resources.NewHost()
		host.ID = hostParam
	case *resources.Host:
		host = hostParam
	}
	if host == nil {
		return nil, scerr.InvalidParameterError("hostParam", "must be a not-empty string or a *resources.Host")
	}

	logrus.Debugf(">>> stacks.aws::WaitHostReady(%s)", host.ID)
	defer logrus.Debugf("<<< stacks.aws::WaitHostReady(%s)", host.ID)

	retryErr := retry.WhileUnsuccessful(
		func() error {
			hostTmp, err := s.InspectHost(host)
			if err != nil {
				logrus.Warn(err)
				return err
			}

			host = hostTmp

			if host.LastState == hoststate.ERROR {
				err = retry.AbortedError(
					"error waiting for host in ready state",
					scerr.Errorf(fmt.Sprintf("last state: %s", host.LastState), nil),
				)
				logrus.Warn(err)
				return err
			}

			if host.LastState != hoststate.STARTED {
				err = scerr.Errorf(fmt.Sprintf("not in ready state (current state: %s)", host.LastState.String()), nil)
				logrus.Warn(err)
				return err
			}
			return nil
		},
		temporal.GetDefaultDelay(),
		timeout,
	)
	if retryErr != nil {
		if _, ok := retryErr.(retry.ErrTimeout); ok {
			return host, scerr.Errorf(
				fmt.Sprintf(
					"timeout waiting to get host '%s' information after %v", host.ID, timeout,
				), retryErr,
			)
		}
		return host, retryErr
	}
	return host, nil
}

func (s *Stack) CreateHost(request resources.HostRequest) (host *resources.Host, userData *userdata.Content, err error) {
	userData = userdata.NewContent()

	resourceName := request.ResourceName
	networks := request.Networks
	hostMustHavePublicIP := request.PublicIP
	keyPairName := request.KeyPair.Name

	if networks == nil || len(networks) == 0 {
		return nil, userData, scerr.Errorf(
			fmt.Sprintf(
				"the host %s must be on at least one network (even if public)", resourceName,
			), nil,
		)
	}

	// If no password is provided, create one
	if request.Password == "" {
		password, err := utils.GeneratePassword(16)
		if err != nil {
			return nil, userData, scerr.Errorf(fmt.Sprintf("failed to generate password: %s", err.Error()), err)
		}
		request.Password = password
	}

	// FIXME: AWS Remove logs
	if len(request.Networks) == 1 {
		if s.Config.BuildSubnetworks {
			logrus.Warnf("We need either recalculate network segments here or pass the data through metadata")
			logrus.Warnf("Working network: %s", spew.Sdump(request.Networks[0]))
		}
	} else {
		logrus.Warnf("Choosing between networks: %s", spew.Sdump(request.Networks))
	}

	err = s.ImportKeyPair(request.KeyPair)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		derr := s.DeleteKeyPair(request.KeyPair.Name)
		if derr != nil {
			logrus.Errorf("failed to delete creation keypair: %v", derr)
		}
	}()

	// The Default Network is the first of the provided list, by convention
	defaultNetwork := request.Networks[0]
	defaultNetworkID := defaultNetwork.ID
	defaultGateway := request.DefaultGateway
	isGateway := defaultGateway == nil && defaultNetwork.Name != resources.SingleHostNetworkName
	defaultGatewayID := ""
	defaultGatewayPrivateIP := ""
	if defaultGateway != nil {
		err := defaultGateway.Properties.LockForRead(hostproperty.NetworkV1).ThenUse(
			func(v data.Clonable) error {
				hostNetworkV1 := v.(*propertiesv1.HostNetwork)
				defaultGatewayPrivateIP = hostNetworkV1.IPv4Addresses[defaultNetworkID]
				defaultGatewayID = defaultGateway.ID
				return nil
			},
		)
		if err != nil {
			return nil, userData, scerr.Wrap(err, "")
		}
	}

	if defaultGateway == nil && !hostMustHavePublicIP {
		return nil, userData, scerr.Errorf(
			fmt.Sprintf("the host %s must have a gateway or be public", resourceName), nil,
		)
	}

	// --- prepares data structures for Provider usage ---

	// Constructs userdata content
	err = userData.Prepare(*s.Config, request, defaultNetwork.CIDR, "")
	if err != nil {
		msg := fmt.Sprintf("failed to prepare user data content: %+v", err)
		logrus.Debugf(utils.Capitalize(msg))
		return nil, userData, scerr.Errorf(fmt.Sprintf(msg), err)
	}

	// Determine system disk size based on vcpus count
	template, err := s.GetTemplate(request.TemplateID)
	if err != nil {
		return nil, userData, scerr.Errorf(fmt.Sprintf("failed to get image: %s", err), err)
	}

	rim, err := s.GetImage(request.ImageID)
	if err != nil {
		return nil, nil, err
	}

	if request.DiskSize > template.DiskSize {
		template.DiskSize = request.DiskSize
	}

	if int(rim.DiskSize) > template.DiskSize {
		template.DiskSize = int(rim.DiskSize)
	}

	if template.DiskSize == 0 {
		// Determines appropriate disk size
		if template.Cores < 16 { // nolint
			template.DiskSize = 100
		} else if template.Cores < 32 {
			template.DiskSize = 200
		} else {
			template.DiskSize = 400
		}
	}

	logrus.Debugf("Selected template: '%s', '%s'", template.ID, template.Name)

	// Select usable availability zone, the first one in the list
	if s.AwsConfig.Zone == "" {
		azList, err := s.ListAvailabilityZones()
		if err != nil {
			return nil, userData, err
		}
		var az string
		for az = range azList {
			break
		}
		s.AwsConfig.Zone = az
		logrus.Debugf("Selected Availability Zone: '%s'", az)
	}

	// --- Initializes resources.Host ---

	host = resources.NewHost()
	host.PrivateKey = request.KeyPair.PrivateKey // Add PrivateKey to host definition
	host.Password = request.Password

	err = host.Properties.LockForWrite(hostproperty.NetworkV1).ThenUse(
		func(v data.Clonable) error {
			hostNetworkV1 := v.(*propertiesv1.HostNetwork)
			hostNetworkV1.DefaultNetworkID = defaultNetworkID
			hostNetworkV1.DefaultGatewayID = defaultGatewayID
			hostNetworkV1.DefaultGatewayPrivateIP = defaultGatewayPrivateIP
			hostNetworkV1.IsGateway = isGateway
			return nil
		},
	)
	if err != nil {
		return nil, userData, err
	}

	// Adds Host property SizingV1
	err = host.Properties.LockForWrite(hostproperty.SizingV1).ThenUse(
		func(v data.Clonable) error {
			hostSizingV1 := v.(*propertiesv1.HostSizing)
			// Note: from there, no idea what was the RequestedSize; caller will have to complement this information
			hostSizingV1.Template = request.TemplateID
			hostSizingV1.AllocatedSize = properties.ModelHostTemplateToPropertyHostSize(template)
			return nil
		},
	)
	if err != nil {
		return nil, userData, err
	}

	// Sets provider parameters to create host
	userDataPhase1, err := userData.Generate("phase1")
	if err != nil {
		return nil, userData, err
	}

	vpcnet, err := s.GetNetworkByName(s.AwsConfig.NetworkName)
	if err != nil {
		return nil, userData, err
	}

	// --- query provider for host creation ---

	logrus.Debugf("requesting host resource creation...")
	var desistError error

	// Retry creation until success, for 10 minutes
	err = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {

			if ok, err := hasSecurityGroup(s.EC2Service, vpcnet.ID, request.ResourceName); err == nil {
				if !ok {
					logrus.Debug("Security group not found")
					err = createSecurityGroup(s.EC2Service, vpcnet.ID, request.ResourceName)
					if err != nil {
						desistError = err
						return nil
					}
				}
			} else {
				logrus.Debugf("Error happened: %v", err)
				desistError = err
				return nil
			}

			sgID, err := getSecurityGroupID(s.EC2Service, vpcnet.ID, request.ResourceName)
			if err != nil {
				desistError = err
				return nil
			}

			var server *resources.Host

			// FIXME: AWS Here the defaultNetwork.ID must be different if the network is splitted
			trick := request.Spot
			if trick {
				netID := defaultNetwork.ID
				if s.Config.BuildSubnetworks && len(defaultNetwork.Subnetworks) >= 2 {
					if isGateway {
						netID = defaultNetwork.Subnetworks[0].ID
					} else {
						netID = defaultNetwork.Subnetworks[1].ID
					}
				}

				server, err = buildAwsSpotMachine(
					s.EC2Service, keyPairName, request.ResourceName, rim.ID, s.AwsConfig.Zone, netID,
					string(userDataPhase1), isGateway, template, sgID,
				)
			} else {
				netID := defaultNetwork.ID
				if s.Config.BuildSubnetworks && len(defaultNetwork.Subnetworks) >= 2 {
					if isGateway {
						netID = defaultNetwork.Subnetworks[0].ID
					} else {
						netID = defaultNetwork.Subnetworks[1].ID
					}
				}

				server, err = buildAwsMachine(
					s.EC2Service, keyPairName, request.ResourceName, rim.ID, s.AwsConfig.Zone, netID,
					string(userDataPhase1), isGateway, template, sgID,
				)
			}
			if err != nil {
				logrus.Warnf("error creating host: %+v", err)

				if server != nil {
					killErr := s.DeleteHost(server.ID)
					if killErr != nil {
						return scerr.Wrap(err, killErr.Error())
					}
				}

				if isAWSErr(err) {
					desistError = err
					return nil
				}

				return err
			}

			if server == nil {
				return scerr.Errorf(fmt.Sprintf("failed to create server"), nil)
			}

			host.ID = server.ID
			host.Name = server.Name

			// Wait until Host is ready, not just until the build is started
			_, err = s.WaitHostReady(host, temporal.GetLongOperationTimeout())
			if err != nil {
				killErr := s.DeleteHost(host.ID)
				if killErr != nil {
					return scerr.Wrap(err, killErr.Error())
				}
				return err
			}

			return nil
		},
		temporal.GetLongOperationTimeout(),
	)
	if err != nil {
		return nil, userData, scerr.Wrap(err, "Error creating host: timeout")
	}
	if desistError != nil {
		return nil, userData, scerr.ForbiddenError(fmt.Sprintf("Error creating host: %s", desistError.Error()))
	}

	logrus.Debugf("host resource created.")

	// Starting from here, delete host if exiting with error
	defer func() {
		if err != nil { // FIXME: Handle error groups
			logrus.Infof("Cleanup, deleting host '%s'", host.Name)
			derr := s.DeleteHost(host.ID)
			if derr != nil {
				logrus.Warnf("Error deleting host: %v", derr)
			}
		}
	}()

	if host == nil {
		return nil, nil, scerr.Errorf(fmt.Sprintf("unexpected nil host"), nil)
	}

	if !host.OK() {
		logrus.Warnf("Missing data in host: %v", host)
	}

	return host, userData, nil

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
	dgo, err := EC2Service.DescribeSecurityGroups(
		&ec2.DescribeSecurityGroupsInput{
			Filters: []*ec2.Filter{
				&ec2.Filter{
					Name:   aws.String("group-name"),
					Values: []*string{aws.String(name)},
				},
			},
		},
	)
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

func getSecurityGroupID(EC2Service *ec2.EC2, vpcID string, name string) (string, error) {
	dgo, err := EC2Service.DescribeSecurityGroups(
		&ec2.DescribeSecurityGroupsInput{
			Filters: []*ec2.Filter{
				&ec2.Filter{
					Name:   aws.String("group-name"),
					Values: []*string{aws.String(name)},
				},
			},
		},
	)
	if err != nil {
		return "", err
	}

	for _, sg := range dgo.SecurityGroups {
		if aws.StringValue(sg.VpcId) == vpcID {
			return aws.StringValue(sg.GroupId), nil
		}
	}

	return "", scerr.NotFoundError(fmt.Sprintf("Security group %s not found", name))
}

func createSecurityGroup(EC2Service *ec2.EC2, vpcID string, name string) error {
	logrus.Warnf("Creating security group for vpc %s with name %s", vpcID, name)

	// Create the security group with the VPC, name and description.
	createRes, err := EC2Service.CreateSecurityGroup(
		&ec2.CreateSecurityGroupInput{
			Description: aws.String(fmt.Sprintf("Default group cfg for vpc %s", vpcID)),
			GroupName:   aws.String(name),
			VpcId:       aws.String(vpcID),
		},
	)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case "InvalidVpcID.NotFound":
				return scerr.Errorf(fmt.Sprintf("unable to find VPC with ID %q.", vpcID), err)
			case "InvalidGroup.Duplicate":
				return scerr.Errorf(fmt.Sprintf("security group %q already exists.", name), err)
			}
		}
		return scerr.Errorf(fmt.Sprintf("unable to create security group %q, %v", name, err), err)
	}
	fmt.Printf(
		"Created security group %s with VPC %s.\n",
		aws.StringValue(createRes.GroupId), vpcID,
	)

	var ports []portDef

	// Add common ports
	ports = append(ports, portDef{"tcp", 22, 22})
	ports = append(ports, portDef{"tcp", 80, 80})
	ports = append(ports, portDef{"tcp", 443, 443})

	// Guacamole ports
	ports = append(ports, portDef{"tcp", 8080, 8080})
	ports = append(ports, portDef{"tcp", 8009, 8009})
	ports = append(ports, portDef{"tcp", 9009, 9009})
	ports = append(ports, portDef{"tcp", 3389, 3389})
	ports = append(ports, portDef{"tcp", 5900, 5900})
	ports = append(ports, portDef{"tcp", 63011, 63011})

	// Add time server
	ports = append(ports, portDef{"udp", 123, 123})

	// Add kubernetes see https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/#check-required-ports
	ports = append(ports, portDef{"tcp", 6443, 6443})
	ports = append(ports, portDef{"tcp", 2379, 2380})
	ports = append(ports, portDef{"tcp", 10250, 10250})
	ports = append(ports, portDef{"tcp", 10251, 10251})
	ports = append(ports, portDef{"tcp", 10252, 10252})
	ports = append(ports, portDef{"tcp", 10255, 10255})
	ports = append(ports, portDef{"tcp", 30000, 32767})

	// Add docker swarm ports
	ports = append(ports, portDef{"tcp", 2376, 2376})
	ports = append(ports, portDef{"tcp", 2377, 2377})
	ports = append(ports, portDef{"tcp", 7946, 7946})
	ports = append(ports, portDef{"udp", 7946, 7946})
	ports = append(ports, portDef{"udp", 4789, 4789})

	// ping
	ports = append(ports, portDef{"icmp", -1, -1})

	var permissions []*ec2.IpPermission
	for _, item := range ports {
		permissions = append(
			permissions, (&ec2.IpPermission{}).
				SetIpProtocol(item.protocol).
				SetFromPort(item.fromPort).
				SetToPort(item.toPort).
				SetIpRanges(
					[]*ec2.IpRange{
						{CidrIp: aws.String("0.0.0.0/0")},
					},
				),
		)
	}

	// Add permissions to the security group
	_, err = EC2Service.AuthorizeSecurityGroupIngress(
		&ec2.AuthorizeSecurityGroupIngressInput{
			GroupId:       createRes.GroupId,
			IpPermissions: permissions,
		},
	)
	if err != nil {
		return scerr.Errorf(fmt.Sprintf("unable to set security group %q ingress, %v", name, err), err)
	}

	return nil
}

func buildAwsSpotMachine(EC2Service *ec2.EC2, keypairName string, name string, imageId string, zone string, netID string, data string, isGateway bool, template *resources.HostTemplate, sgID string) (*resources.Host, error) {
	ni := &ec2.InstanceNetworkInterfaceSpecification{
		DeviceIndex:              aws.Int64(int64(0)),
		SubnetId:                 aws.String(netID),
		AssociatePublicIpAddress: aws.Bool(isGateway),
		Groups:                   []*string{aws.String(sgID)},
	}

	dspho, err := EC2Service.DescribeSpotPriceHistory(
		&ec2.DescribeSpotPriceHistoryInput{
			AvailabilityZone:    aws.String(zone),
			InstanceTypes:       []*string{aws.String(template.ID)},
			ProductDescriptions: []*string{aws.String("Linux/UNIX")},
		},
	)
	if err != nil {
		return nil, err
	}

	lastPrice := dspho.SpotPriceHistory[len(dspho.SpotPriceHistory)-1]
	logrus.Warnf("Last price detected %s", aws.StringValue(lastPrice.SpotPrice))

	input := &ec2.RequestSpotInstancesInput{
		InstanceCount: aws.Int64(1),
		LaunchSpecification: &ec2.RequestSpotLaunchSpecification{
			ImageId:      aws.String(imageId),
			InstanceType: aws.String(template.ID),
			KeyName:      aws.String(keypairName),
			BlockDeviceMappings: []*ec2.BlockDeviceMapping{
				&ec2.BlockDeviceMapping{
					DeviceName: aws.String("/dev/sda1"),
					NoDevice:   aws.String(""),
					Ebs: &ec2.EbsBlockDevice{
						DeleteOnTermination: aws.Bool(true),
						VolumeSize:          aws.Int64(int64(template.DiskSize)),
					},
				},
			},
			NetworkInterfaces: []*ec2.InstanceNetworkInterfaceSpecification{ni},
			Placement: &ec2.SpotPlacement{
				AvailabilityZone: aws.String(zone),
			},
			UserData: aws.String(base64.StdEncoding.EncodeToString([]byte(data))),
		},
		SpotPrice: lastPrice.SpotPrice, // FIXME: Round up
		Type:      aws.String("one-time"),
	}

	result, err := EC2Service.RequestSpotInstances(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				return nil, aerr
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			return nil, err
		}
	}

	instance := result.SpotInstanceRequests[0]

	// FIXME: Listen to result.SpotInstanceRequests[0].State

	host := resources.Host{
		ID:   aws.StringValue(instance.InstanceId),
		Name: name,
	}
	return &host, nil
}

func buildAwsMachine(EC2Service *ec2.EC2, keypairName string, name string, imageId string, zone string, netID string, data string, isGateway bool, template *resources.HostTemplate, sgID string) (*resources.Host, error) {
	logrus.Warnf("Using %s as subnetwork, looking for group %s", netID, sgID)

	ni := &ec2.InstanceNetworkInterfaceSpecification{
		DeviceIndex:              aws.Int64(int64(0)),
		SubnetId:                 aws.String(netID),
		AssociatePublicIpAddress: aws.Bool(isGateway),
		Groups:                   []*string{aws.String(sgID)},
	}

	// Run instance
	out, err := EC2Service.RunInstances(
		&ec2.RunInstancesInput{
			ImageId:      aws.String(imageId),
			InstanceType: aws.String(template.ID),
			KeyName:      aws.String(keypairName),
			MaxCount:     aws.Int64(1),
			MinCount:     aws.Int64(1),
			Placement: &ec2.Placement{
				AvailabilityZone: aws.String(zone),
			},
			BlockDeviceMappings: []*ec2.BlockDeviceMapping{
				&ec2.BlockDeviceMapping{
					DeviceName: aws.String("/dev/sda1"),
					NoDevice:   aws.String(""),
					Ebs: &ec2.EbsBlockDevice{
						DeleteOnTermination: aws.Bool(true),
						VolumeSize:          aws.Int64(int64(template.DiskSize)),
					},
				},
			},
			NetworkInterfaces: []*ec2.InstanceNetworkInterfaceSpecification{ni},
			TagSpecifications: []*ec2.TagSpecification{
				&ec2.TagSpecification{
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
		},
	)
	if err != nil {
		if isAWSErr(err) {
			return nil, err
		}
		return nil, err
	}

	_, err = EC2Service.ModifyInstanceAttribute(
		&ec2.ModifyInstanceAttributeInput{
			InstanceId:      out.Instances[0].InstanceId,
			SourceDestCheck: &ec2.AttributeBooleanValue{Value: aws.Bool(false)},
		},
	)
	if err != nil {
		return nil, err
	}

	instance := out.Instances[0]

	host := resources.Host{
		ID:   aws.StringValue(instance.InstanceId),
		Name: name,
	}
	return &host, nil
}

func (s *Stack) InspectHost(hostParam interface{}) (host *resources.Host, err error) {
	switch hostParam := hostParam.(type) {
	case string:
		host = resources.NewHost()
		host.ID = hostParam
	case *resources.Host:
		host = hostParam
	}

	if host == nil {
		return nil, scerr.InvalidParameterError("hostParam", "must be a string or a *resources.Host")
	}

	hostRef := host.ID

	if utils.IsEmpty(host) {
		return nil, resources.ResourceNotFoundError("host", hostRef)
	}

	awsHost, err := s.EC2Service.DescribeInstances(
		&ec2.DescribeInstancesInput{
			Filters: []*ec2.Filter{
				&ec2.Filter{
					Name:   aws.String("instance-id"),
					Values: []*string{aws.String(hostRef)},
				},
			},
		},
	)
	if err != nil {
		return nil, err
	}

	if len(awsHost.Reservations) == 0 {
		awsHost, err = s.EC2Service.DescribeInstances(
			&ec2.DescribeInstancesInput{
				Filters: []*ec2.Filter{
					&ec2.Filter{
						Name: aws.String("tag:Name"),
						Values: []*string{
							aws.String(hostRef),
						},
					},
				},
			},
		)
		if err != nil {
			return nil, err
		}
	}

	if len(awsHost.Reservations) == 0 {
		return nil, scerr.NotFoundError(fmt.Sprintf("host %s not found", hostRef))
	}

	instanceName := ""
	instanceType := ""

	for _, r := range awsHost.Reservations {
		for _, i := range r.Instances {
			host.LastState, err = getAwsInstanceState(i.State)
			if err != nil {
				return nil, err
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
		return nil, scerr.Errorf(fmt.Sprintf("error recovering instance type of %s", hostRef), nil)
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
	netnamebyid := make(map[string]string)
	netidbyname := make(map[string]string)

	ipv4 := ""
	for _, rn := range subnets {
		ip4bynetid[rn.ID] = rn.IP
		netnamebyid[rn.ID] = rn.Name
		netidbyname[rn.Name] = rn.ID
		if rn.PublicIP != "" {
			ipv4 = rn.PublicIP
		}
	}

	err = host.Properties.LockForWrite(hostproperty.NetworkV1).ThenUse(
		func(v data.Clonable) error {
			hostNetworkV1 := v.(*propertiesv1.HostNetwork)
			hostNetworkV1.IPv4Addresses = ip4bynetid
			hostNetworkV1.IPv6Addresses = make(map[string]string)
			hostNetworkV1.NetworksByID = netnamebyid
			hostNetworkV1.NetworksByName = netidbyname
			if hostNetworkV1.PublicIPv4 == "" {
				hostNetworkV1.PublicIPv4 = ipv4
			}
			return nil
		},
	)
	if err != nil {
		return nil, scerr.Errorf(fmt.Sprintf("failed to update hostproperty.NetworkV1 : %s", err.Error()), err)
	}

	allocated := fromMachineTypeToAllocatedSize(s, instanceType)

	err = host.Properties.LockForWrite(hostproperty.SizingV1).ThenUse(
		func(v data.Clonable) error {
			hostSizingV1 := v.(*propertiesv1.HostSizing)
			hostSizingV1.AllocatedSize.Cores = allocated.Cores
			hostSizingV1.AllocatedSize.RAMSize = allocated.RAMSize
			hostSizingV1.AllocatedSize.DiskSize = allocated.DiskSize
			return nil
		},
	)
	if err != nil {
		return nil, scerr.Errorf(fmt.Sprintf("failed to update hostproperty.SizingV1 : %s", err.Error()), err)
	}

	host.Name = instanceName

	if !host.OK() {
		logrus.Warnf("[TRACE] Unexpected host status: %s", spew.Sdump(host))
	}

	return host, nil
}

func fromMachineTypeToAllocatedSize(stack *Stack, machineType string) propertiesv1.HostSize {
	hz := propertiesv1.HostSize{}

	templates, err := stack.ListTemplates()
	if err != nil {
		return hz
	}

	for _, template := range templates {
		if template.Name == machineType {
			hz.Cores = template.Cores
			hz.CPUFreq = template.CPUFreq
			hz.DiskSize = template.DiskSize
			hz.RAMSize = template.RAMSize
			hz.GPUNumber = template.GPUNumber
			hz.GPUType = template.GPUType
			break
		}
	}

	return hz
}

func getTagOfSubnet(EC2Service *ec2.EC2, SubnetId *string, s string) string {
	sno, err := EC2Service.DescribeSubnets(
		&ec2.DescribeSubnetsInput{
			SubnetIds: []*string{SubnetId},
		},
	)
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

func (s *Stack) GetHostByName(name string) (_ *resources.Host, err error) {
	hosts, err := s.ListHosts()
	if err != nil {
		return nil, err
	}

	for _, host := range hosts {
		if host.Name == name {
			return host, nil
		}
	}

	return nil, resources.ResourceNotFoundError("host", name)
}

func (s *Stack) GetHostState(hostParam interface{}) (_ hoststate.Enum, err error) {
	host, err := s.InspectHost(hostParam)
	if err != nil {
		return hoststate.ERROR, err
	}

	return host.LastState, nil
}

func (s *Stack) ListHosts() ([]*resources.Host, error) {
	var hosts []*resources.Host

	dio, err := s.EC2Service.DescribeInstances(&ec2.DescribeInstancesInput{})
	if err != nil {
		return hosts, err
	}

	for _, reservation := range dio.Reservations {
		if reservation != nil {
			for _, instance := range reservation.Instances {
				if instance != nil {
					state, _ := getAwsInstanceState(instance.State)
					name := ""

					for _, tag := range instance.Tags {
						if aws.StringValue(tag.Key) == "Name" {
							if aws.StringValue(tag.Value) != "" {
								name = aws.StringValue(tag.Value)
							}
						}
					}

					hosts = append(
						hosts, &resources.Host{
							ID:         aws.StringValue(instance.InstanceId),
							Name:       name,
							LastState:  state,
							Properties: nil,
						},
					)
				}
			}
		}
	}

	return hosts, nil
}

func (s *Stack) DeleteHost(id string) error {
	ips, err := s.EC2Service.DescribeAddresses(
		&ec2.DescribeAddressesInput{
			Filters: []*ec2.Filter{
				&ec2.Filter{
					Name:   aws.String("instance-id"),
					Values: []*string{aws.String(id)},
				},
			},
		},
	)
	if err != nil {
		if ips != nil {
			for _, ip := range ips.Addresses {
				_, _ = s.EC2Service.ReleaseAddress(
					&ec2.ReleaseAddressInput{
						AllocationId: ip.AllocationId,
					},
				)
			}
		}
	}

	dio, err := s.EC2Service.DescribeInstances(
		&ec2.DescribeInstancesInput{
			InstanceIds: []*string{aws.String(id)},
		},
	)
	if err != nil {
		return err
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
	_, err = s.EC2Service.TerminateInstances(
		&ec2.TerminateInstancesInput{
			InstanceIds: []*string{aws.String(id)},
		},
	)
	if err != nil {
		return err
	}

	retryErr := retry.WhileUnsuccessful(
		func() error {
			hostTmp, err := s.InspectHost(id)
			if err != nil {
				return err
			}

			if !(hostTmp.LastState == hoststate.STOPPED || hostTmp.LastState == hoststate.TERMINATED) {
				return scerr.Errorf(
					fmt.Sprintf(
						"not in stopped or terminated state (current state: %s)", hostTmp.LastState.String(),
					), nil,
				)
			}
			return nil
		},
		temporal.GetDefaultDelay(),
		temporal.GetHostCleanupTimeout(),
	)
	if retryErr != nil {
		if _, ok := retryErr.(retry.ErrTimeout); ok {
			return scerr.Errorf(
				fmt.Sprintf(
					"timeout waiting to get host '%s' information after %v", id, temporal.GetHostCleanupTimeout(),
				), retryErr,
			)
		}
		return retryErr
	}

	// Delete volumes if there, mark errors as warnings
	for _, volume := range attachedVolumes {
		_, err = s.EC2Service.DeleteVolume(
			&ec2.DeleteVolumeInput{
				VolumeId: aws.String(volume),
			},
		)
		if err != nil {
			logrus.Warnf("problem cleaning up, deleting volume %s", volume)
		}
	}

	// Delete security group
	if secGroupId != "" {
		_, err = s.EC2Service.DeleteSecurityGroup(
			&ec2.DeleteSecurityGroupInput{
				GroupId: aws.String(secGroupId),
			},
		)
		if err != nil {
			return scerr.Wrap(err, "error deleting security group")
		}
	} else {
		logrus.Warnf("security group %s for host %s not found", secGroupId, id)
	}

	// Delete keypair
	if keyPairName != "" {
		_, err = s.EC2Service.DeleteKeyPair(
			&ec2.DeleteKeyPairInput{
				KeyName: aws.String(keyPairName),
			},
		)
		if err != nil {
			return scerr.Wrap(err, "error deleting keypair")
		}
	} else {
		logrus.Warnf("keypair %s for host %s not found", keyPairName, id)
	}

	return err
}

func (s *Stack) StopHost(id string) error {
	_, err := s.EC2Service.StopInstances(
		&ec2.StopInstancesInput{
			Force:       aws.Bool(true),
			InstanceIds: []*string{aws.String(id)},
		},
	)
	if err != nil {
		return err
	}

	retryErr := retry.WhileUnsuccessful(
		func() error {
			hostTmp, err := s.InspectHost(id)
			if err != nil {
				return err
			}

			if !(hostTmp.LastState == hoststate.STOPPED || hostTmp.LastState == hoststate.TERMINATED) {
				return scerr.Errorf(
					fmt.Sprintf(
						"not in stopped or terminated state (current state: %s)", hostTmp.LastState.String(),
					), nil,
				)
			}
			return nil
		},
		temporal.GetDefaultDelay(),
		temporal.GetHostCleanupTimeout(),
	)
	if retryErr != nil {
		if _, ok := retryErr.(retry.ErrTimeout); ok {
			return scerr.Errorf(
				fmt.Sprintf(
					"timeout waiting to get host '%s' information after %v", id, temporal.GetHostCleanupTimeout(),
				), retryErr,
			)
		}
		return retryErr
	}

	return err
}

func (s *Stack) StartHost(id string) error {
	_, err := s.EC2Service.StartInstances(
		&ec2.StartInstancesInput{
			InstanceIds: []*string{aws.String(id)},
		},
	)
	if err != nil {
		return err
	}

	retryErr := retry.WhileUnsuccessful(
		func() error {
			hostTmp, err := s.InspectHost(id)
			if err != nil {
				return err
			}

			if hostTmp.LastState != hoststate.STARTED {
				return scerr.Errorf(
					fmt.Sprintf("not in started state (current state: %s)", hostTmp.LastState.String()), nil,
				)
			}
			return nil
		},
		temporal.GetDefaultDelay(),
		temporal.GetHostCleanupTimeout(),
	)
	if retryErr != nil {
		if _, ok := retryErr.(retry.ErrTimeout); ok {
			return scerr.Errorf(
				fmt.Sprintf(
					"timeout waiting to get host '%s' information after %v", id, temporal.GetHostCleanupTimeout(),
				), retryErr,
			)
		}
		return retryErr
	}

	return err
}

func (s *Stack) RebootHost(id string) error {
	_, err := s.EC2Service.RebootInstances(
		&ec2.RebootInstancesInput{
			InstanceIds: []*string{aws.String(id)},
		},
	)
	if err != nil {
		return err
	}

	retryErr := retry.WhileUnsuccessful(
		func() error {
			hostTmp, err := s.InspectHost(id)
			if err != nil {
				return err
			}

			if hostTmp.LastState != hoststate.STARTED {
				return scerr.Errorf(
					fmt.Sprintf("not in started state (current state: %s)", hostTmp.LastState.String()), nil,
				)
			}
			return nil
		},
		temporal.GetDefaultDelay(),
		2*temporal.GetHostCleanupTimeout(),
	)
	if retryErr != nil {
		if _, ok := retryErr.(retry.ErrTimeout); ok {
			return scerr.Errorf(
				fmt.Sprintf(
					"timeout waiting to get host '%s' information after %v", id, temporal.GetHostCleanupTimeout(),
				), retryErr,
			)
		}
		return retryErr
	}

	return err
}

func (s *Stack) ResizeHost(id string, request resources.SizingRequirements) (*resources.Host, error) {
	return nil, scerr.NotImplementedError("ResizeHost() not implemented yet") // FIXME: Technical debt
}
