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
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/pricing"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// CreateKeyPair creates a keypair and upload it to AWS
func (s stack) CreateKeyPair(name string) (_ *abstract.KeyPair, xerr fail.Error) {
	nullAKP := &abstract.KeyPair{}
	if s.IsNull() {
		return nullAKP, fail.InvalidInstanceError()
	}
	if name == "" {
		return nullAKP, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "('%s')", name).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&xerr)

	keypair, xerr := abstract.NewKeyPair(name)
	if xerr != nil {
		return nil, xerr
	}

	if xerr = s.rpcImportKeyPair(aws.String(keypair.Name), []byte(keypair.PublicKey)); xerr != nil {
		return nullAKP, xerr
	}
	return keypair, nil
}

// ImportKeyPair imports an existing resources.KeyPair to AWS (not in the interface yet, but will come soon)
func (s stack) ImportKeyPair(keypair *abstract.KeyPair) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if keypair == nil {
		return fail.InvalidParameterError("keypair", "cannot be nil")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%v)", keypair).
		WithStopwatch().
		Entering().
		Exiting()
	defer fail.OnExitTraceError(&xerr)

	return s.rpcImportKeyPair(aws.String(keypair.Name), []byte(keypair.PublicKey))
}

// InspectKeyPair loads a keypair from AWS
// Note: the private key is not stored by AWS...
func (s stack) InspectKeyPair(id string) (_ *abstract.KeyPair, xerr fail.Error) {
	nullAKP := &abstract.KeyPair{}
	if s.IsNull() {
		return nullAKP, fail.InvalidInstanceError()
	}
	if id == "" {
		return nullAKP, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).
		WithStopwatch().
		Entering().
		Exiting()
	defer fail.OnExitTraceError(&xerr)

	resp, xerr := s.rpcDescribeKeyPairByID(aws.String(id))
	if xerr != nil {
		return nullAKP, xerr
	}

	out := toAbstractKeyPair(*resp)
	return &out, nil
}

func toAbstractKeyPair(in ec2.KeyPairInfo) abstract.KeyPair {
	out := abstract.KeyPair{}
	out.ID = aws.StringValue(in.KeyPairId)
	out.Name = aws.StringValue(in.KeyName)
	out.PublicKey = aws.StringValue(in.KeyFingerprint)
	return out
}

// ListKeyPairs lists keypairs stored in AWS
func (s stack) ListKeyPairs() (_ []abstract.KeyPair, xerr fail.Error) {
	var emptySlice []abstract.KeyPair
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute")).
		WithStopwatch().
		Entering().
		Exiting()
	defer fail.OnExitTraceError(&xerr)

	resp, xerr := s.rpcDescribeKeyPairs(nil)
	if xerr != nil {
		return emptySlice, xerr
	}
	var keys []abstract.KeyPair
	for _, kp := range resp {
		keys = append(keys, toAbstractKeyPair(*kp))
	}
	return keys, nil
}

// DeleteKeyPair deletes a keypair from AWS
func (s stack) DeleteKeyPair(id string) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&xerr)

	return s.rpcDeleteKeyPair(aws.String(id))
}

// ListAvailabilityZones lists AWS availability zones available
func (s stack) ListAvailabilityZones() (_ map[string]bool, xerr fail.Error) {
	emptyMap := map[string]bool{}
	if s.IsNull() {
		return emptyMap, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute")).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&xerr)

	resp, xerr := s.rpcDescribeAvailabilityZones(nil)
	if xerr != nil {
		return emptyMap, xerr
	}
	if len(resp) > 0 {
		zones := make(map[string]bool, len(resp))
		for _, zone := range resp {
			zoneName := aws.StringValue(zone.ZoneName)
			if zoneName != "" {
				zones[zoneName] = aws.StringValue(zone.State) == "available"
			}
		}
		return zones, nil
	}

	return emptyMap, nil
}

// ListRegions lists regions available in AWS
func (s stack) ListRegions() (_ []string, xerr fail.Error) {
	var emptySlice []string
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute")).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&xerr)

	resp, xerr := s.rpcDescribeRegions(nil)
	if xerr != nil {
		return emptySlice, xerr
	}
	if len(resp) > 0 {
		regions := make([]string, 0, len(resp))
		for _, region := range resp {
			regions = append(regions, aws.StringValue(region.RegionName))
		}
		return regions, nil
	}

	return emptySlice, nil
}

// InspectImage loads information about an image stored in AWS
func (s stack) InspectImage(id string) (_ *abstract.Image, xerr fail.Error) {
	nullAI := &abstract.Image{}
	if s.IsNull() {
		return nullAI, fail.InvalidInstanceError()
	}
	if id == "" {
		return nullAI, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&xerr)

	resp, xerr := s.rpcDescribeImageByID(aws.String(id))
	if xerr != nil {
		return nullAI, xerr
	}

	out := toAbstractImage(*resp)
	return &out, nil
}

// InspectTemplate loads information about a template stored in AWS
func (s stack) InspectTemplate(id string) (template *abstract.HostTemplate, xerr fail.Error) {
	nullAHT := &abstract.HostTemplate{}
	if s.IsNull() {
		return nullAHT, fail.InvalidInstanceError()
	}
	if id == "" {
		return nullAHT, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&xerr)

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
		return nullAHT, normalizeError(err)
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

		return &tpl, nil
	}

	return nullAHT, abstract.ResourceNotFoundError("template", id)
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
		aws.String("125523088429"), // CentOS 8
		aws.String("161831738826"), // Centos 7 with ENA
		aws.String("057448758665"), // Centos 7
		aws.String("679593333241"), // Centos 6 AND Others
		aws.String("595879546273"), // CoreOS
	}
	filters = append(filters, &ec2.Filter{
		Name:   aws.String("owner-id"),
		Values: owners,
	})
	return filters
}

// ListImages lists available image
func (s stack) ListImages() (_ []abstract.Image, xerr fail.Error) {
	var emptySlice []abstract.Image
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute")).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&xerr)

	resp, xerr := s.rpcDescribeImages(nil)
	if xerr != nil {
		return emptySlice, xerr
	}
	if len(resp) > 0 {
		images := make([]abstract.Image, 0, len(resp))
		for _, image := range resp {
			if image != nil {
				if !aws.BoolValue(image.EnaSupport) {
					logrus.Warnf("ENA filtering does NOT actually work!")
				}

				images = append(images, toAbstractImage(*image))
			}
		}
		return images, nil
	}

	return emptySlice, nil
}

func toAbstractImage(in ec2.Image) abstract.Image {
	return abstract.Image{
		ID:          aws.StringValue(in.ImageId),
		Name:        aws.StringValue(in.Name),
		Description: aws.StringValue(in.Description),
		StorageType: aws.StringValue(in.RootDeviceType),
	}
}

// ListTemplates lists templates stored in AWS
func (s stack) ListTemplates() (templates []abstract.HostTemplate, xerr fail.Error) {
	var emptySlice []abstract.HostTemplate
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute")).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&xerr)

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
		return emptySlice, normalizeError(err)
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
func (s stack) WaitHostReady(hostParam stacks.HostParameter, timeout time.Duration) (_ *abstract.HostCore, xerr fail.Error) {
	nullAHC := abstract.NewHostCore()
	if s.IsNull() {
		return nullAHC, fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return nullAHC, xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s, %v)", hostRef, timeout).WithStopwatch().Entering().Exiting()
	defer fail.OnPanic(&xerr)
	defer fail.OnExitTraceError(&xerr)

	retryErr := retry.WhileUnsuccessful(
		func() error {
			hostTmp, innerXErr := s.InspectHost(ahf)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					return retry.StopRetryError(innerXErr)
				default:
					return innerXErr
				}
			}

			ahf = hostTmp

			if hostTmp.CurrentState == hoststate.ERROR {
				innerXErr = retry.StopRetryError(fail.NewError("last state: %s", hostTmp.CurrentState.String()), "error waiting for host in ready state")
				// logrus.Warn(innerXErr.Error())
				return innerXErr
			}

			if hostTmp.CurrentState != hoststate.STARTED {
				// innerXErr = fail.NewError("not in ready state (current state: %s)", ahf.CurrentState.String())
				logrus.Warn(innerXErr.Error())
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
			return nullAHC, fail.ToError(retryErr.Cause())
		case *retry.ErrTimeout:
			return nullAHC, fail.Wrap(retryErr.Cause(), "timeout waiting to get host '%s' information after %v", ahf.GetID(), timeout)
		default:
			return nullAHC, retryErr
		}
	}
	return ahf.Core, nil
}

// CreateHost creates a host
func (s stack) CreateHost(request abstract.HostRequest) (ahf *abstract.HostFull, userData *userdata.Content, xerr fail.Error) {
	nullAHF := abstract.NewHostFull()
	nullUDC := userdata.NewContent()
	if s.IsNull() {
		return nullAHF, nullUDC, fail.InvalidInstanceError()
	}
	if request.KeyPair == nil {
		return nullAHF, nullUDC, fail.InvalidParameterError("request.KeyPair", "cannot be nil")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%v)", request).WithStopwatch().Entering().Exiting()
	defer fail.OnPanic(&xerr)
	defer fail.OnExitTraceError(&xerr)

	resourceName := request.ResourceName
	subnets := request.Subnets
	// hostMustHavePublicIP := request.PublicIP
	keyPairName := request.KeyPair.Name

	if len(subnets) == 0 {
		return nullAHF, nullUDC, fail.InvalidRequestError("the Host '%s' must be on at least one Subnet (even if public)", resourceName)
	}

	// If no password is provided, create one
	if request.Password == "" {
		password, err := utils.GeneratePassword(16)
		if err != nil {
			return nullAHF, nullUDC, fail.Wrap(err, "failed to generate password")
		}
		request.Password = password
	}

	// The default Subnet is the first of the provided list, by convention
	defaultSubnet, defaultSubnetID := func() (*abstract.Subnet, string) {
		if len(request.Subnets) == 0 {
			return nil, ""
		}
		return request.Subnets[0], request.Subnets[0].ID
	}()
	isGateway := request.IsGateway // && defaultNet != nil && defaultNet.Name != abstract.SingleHostNetworkName

	if defaultSubnet == nil {
		if !request.PublicIP {
			return nullAHF, nullUDC, abstract.ResourceInvalidRequestError("host creation", "cannot create a host without public IP or attached network")
		}
		// FIXME: fallback to net-safescale ?
	}

	// defaultSubnet := request.Networks[0]
	// defaultGateway := request.DefaultGateway
	// isGateway := defaultGateway == nil && defaultSubnet.Name != abstract.SingleHostNetworkName
	// defaultGatewayID := ""
	// defaultGatewayPrivateIP := ""
	// if defaultGateway != nil {
	//	xerr = defaultGateway.Properties.Inspect(hostproperty.NetworkV1, func(v data.Clonable) fail.Error {
	//		hostNetworkV1 := v.(*propertiesv1.HostNetworking)
	//		defaultGatewayPrivateIP = hostNetworkV1.IPv4Addresses[defaultNetwork]
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
		return nullAHF, nullUDC, fail.Wrap(xerr, "failed to prepare user data content")
	}

	// Determine system disk size based on vcpus count
	template, xerr := s.InspectTemplate(request.TemplateID)
	if xerr != nil {
		return nullAHF, nullUDC, fail.Wrap(xerr, "failed to get host template '%s'", request.TemplateID)
	}

	rim, xerr := s.InspectImage(request.ImageID)
	if xerr != nil {
		return nullAHF, nullUDC, fail.Wrap(xerr, "failed to get image '%s'", request.ImageID)
	}

	logrus.Debugf("Selected template: '%s', '%s'", template.ID, template.Name)

	// Select usable availability zone, the first one in the list
	if s.AwsConfig.Zone == "" {
		azList, xerr := s.ListAvailabilityZones()
		if xerr != nil {
			return nullAHF, nullUDC, xerr
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

	ahf.Networking.DefaultSubnetID = defaultSubnetID
	ahf.Networking.IsGateway = isGateway

	// Adds Host property SizingV1
	ahf.Sizing = converters.HostTemplateToHostEffectiveSizing(*template)

	// Sets provider parameters to create ahf
	userDataPhase1, xerr := userData.Generate(userdata.PHASE1_INIT)
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}

	// --- query provider for ahf creation ---

	logrus.Debugf("requesting host resource creation...")
	// var desistError error

	// Retry creation until success, for 10 minutes
	xerr = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			var (
				server    *abstract.HostCore
				innerXErr fail.Error
			)
			if request.Disposable {
				server, innerXErr = s.buildAwsSpotMachine(keyPairName, request.ResourceName, rim.ID, s.AwsConfig.Zone, defaultSubnet.ID, string(userDataPhase1), isGateway, *template)
			} else {
				server, innerXErr = s.buildAwsMachine(keyPairName, request.ResourceName, rim.ID, s.AwsConfig.Zone, defaultSubnet.ID, string(userDataPhase1), isGateway, *template)
			}
			if innerXErr != nil {
				logrus.Warnf("error creating Host: %+v", innerXErr)

				if server != nil && server.ID != "" {
					if derr := s.DeleteHost(server.ID); derr != nil {
						_ = innerXErr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Host '%s'", server.Name))
					}
				}

				// if isAWSErr(innerXErr) {
				// 	desistError = xerr
				// 	return nil
				// }

				return innerXErr
			}

			if server == nil {
				return fail.NewError(nil, "failed to create server")
			}

			ahf.Core.ID = server.ID
			ahf.Core.Name = server.Name

			// Wait until Host is ready, not just until the build is started
			if _, innerXErr = s.WaitHostReady(ahf, temporal.GetLongOperationTimeout()); innerXErr != nil {
				if derr := s.DeleteHost(ahf.Core.ID); derr != nil {
					_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Host"))
				}
				return innerXErr
			}

			return nil
		},
		temporal.GetLongOperationTimeout(),
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry:
			return nullAHF, nullUDC, fail.ToError(xerr.Cause())
		case *fail.ErrTimeout:
			return nullAHF, nullUDC, fail.Wrap(xerr.Cause(), "failed to create Host because of timeout")
		default:
			return nullAHF, nullUDC, xerr
		}
	}
	// if desistError != nil {
	// 	return nullAHF, nullUDC, fail.ForbiddenError("failed to create Host: %s", desistError.Error())
	// }

	logrus.Debugf("Host resource created.")

	// Starting from here, delete host if exiting with error
	defer func() {
		if xerr != nil && !request.KeepOnFailure { // FIXME: Handle error groups
			logrus.Infof("Cleanup, deleting host '%s'", ahf.Core.Name)
			if derr := s.DeleteHost(ahf.Core.ID); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Host"))
				logrus.Warnf("Error deleting ahf: %v", derr)
			}
		}
	}()

	if ahf.IsNull() {
		return nullAHF, nullUDC, fail.InconsistentError("unexpected nil ahf")
	}

	if !ahf.OK() {
		logrus.Warnf("Missing data in ahf: %v", ahf)
	}

	return ahf, userData, nil

}

//// Returns true if the error is of type awserr.Error
//func isSpecificAWSErr(err error, code string, message string) bool {
//	if err, ok := err.(awserr.Error); ok {
//		logrus.Warnf("Received AWS error code: %s", err.Code())
//		return err.Code() == code && strings.Contains(err.Message(), message)
//	}
//	return false
//}

// /*
// Returns true if the error matches all these conditions:
// - err if of type awserr.Error
// - Error.Code() matches code
// - Error.Message() contains message
// */
// func isAWSErr(err error) bool {
// 	if err, ok := err.(awserr.Error); ok {
// 		logrus.Warnf("Received AWS error code: %s", err.Code())
// 		return true
// 	}
//
// 	return false
// }

//func hasSecurityGroup(EC2Service *ec2.EC2, vpcID string, name string) (bool, error) {
//	dgo, err := EC2Service.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
//		Filters: []*ec2.Filter{{
//			Name:   aws.String("group-name"),
//			Values: []*string{aws.String(name)},
//		}},
//	})
//	if err != nil {
//		return false, err
//	}
//
//	for _, sg := range dgo.SecurityGroups {
//		if aws.StringValue(sg.VpcId) == vpcID {
//			return true, nil
//		}
//	}
//
//	return false, nil
//}

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

func (s stack) buildAwsSpotMachine(
	keypairName string,
	name string,
	imageId string,
	zone string,
	netID string,
	data string,
	isGateway bool,
	template abstract.HostTemplate,
	//sgID string,
) (*abstract.HostCore, fail.Error) {

	ni := &ec2.InstanceNetworkInterfaceSpecification{
		DeviceIndex:              aws.Int64(int64(0)),
		SubnetId:                 aws.String(netID),
		AssociatePublicIpAddress: aws.Bool(isGateway),
		//Groups:                   []*string{aws.String(sgID)},
	}
	var resp *ec2.DescribeSpotPriceHistoryOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.EC2Service.DescribeSpotPriceHistory(&ec2.DescribeSpotPriceHistoryInput{
				AvailabilityZone:    aws.String(zone),
				InstanceTypes:       []*string{aws.String(template.ID)},
				ProductDescriptions: []*string{aws.String("Linux/UNIX")},
			})
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	lastPrice := resp.SpotPriceHistory[len(resp.SpotPriceHistory)-1]
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
	var result *ec2.RequestSpotInstancesOutput
	xerr = stacks.RetryableRemoteCall(
		func() (err error) {
			result, err = s.EC2Service.RequestSpotInstances(input)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	instance := result.SpotInstanceRequests[0]

	// FIXME: Listen to result.SpotInstanceRequests[0].State

	host := abstract.HostCore{
		ID:   aws.StringValue(instance.InstanceId),
		Name: name,
	}
	return &host, nil
}

func (s stack) buildAwsMachine(
	keypairName string,
	name string,
	imageId string,
	zone string,
	netID string,
	data string,
	isGateway bool,
	template abstract.HostTemplate,
	//sgID string,
) (*abstract.HostCore, fail.Error) {

	//logrus.Warnf("Using %s as subnetwork, looking for group %s", netID, sgID)

	ni := &ec2.InstanceNetworkInterfaceSpecification{
		DeviceIndex:              aws.Int64(int64(0)),
		SubnetId:                 aws.String(netID),
		AssociatePublicIpAddress: aws.Bool(isGateway),
		//Groups:                   []*string{aws.String(sgID)},
	}

	// Run instance
	var resp *ec2.Reservation
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = s.EC2Service.RunInstances(&ec2.RunInstancesInput{
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
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	xerr = stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.ModifyInstanceAttribute(&ec2.ModifyInstanceAttributeInput{
				InstanceId:      resp.Instances[0].InstanceId,
				SourceDestCheck: &ec2.AttributeBooleanValue{Value: aws.Bool(false)},
			})
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	instance := resp.Instances[0]

	hostCore := abstract.HostCore{
		ID:   aws.StringValue(instance.InstanceId),
		Name: name,
	}
	return &hostCore, nil
}

// InspectHost loads information of a host from AWS
func (s stack) InspectHost(hostParam stacks.HostParameter) (ahf *abstract.HostFull, xerr fail.Error) {
	nullAHF := abstract.NewHostFull()
	if s.IsNull() {
		return nullAHF, fail.InvalidInstanceError()
	}
	var hostLabel string
	ahf, hostLabel, xerr = stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return nullAHF, xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostLabel).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&xerr)
	defer fail.OnPanic(&xerr)

	var resp *ec2.Instance
	if ahf.Core.ID != "" {
		resp, xerr = s.rpcDescribeInstanceByID(aws.String(ahf.Core.ID))
	} else {
		resp, xerr = s.rpcDescribeInstanceByName(aws.String(ahf.Core.Name))
	}
	if xerr != nil {
		return nullAHF, xerr
	}
	xerr = s.inspectInstance(ahf, hostLabel, resp)
	return ahf, xerr
}

func (s stack) inspectInstance(ahf *abstract.HostFull, hostLabel string, instance *ec2.Instance) (xerr fail.Error) {
	instanceName := ""
	instanceType := ""

	if ahf.CurrentState, xerr = toHostState(instance.State); xerr != nil {
		return xerr
	}
	ahf.Core.LastState = ahf.CurrentState

	for _, tag := range instance.Tags {
		if tag != nil && (aws.StringValue(tag.Key) == tagNameLabel || aws.StringValue(tag.Key) == "tag:"+tagNameLabel) && aws.StringValue(tag.Value) != "" {
			instanceName = aws.StringValue(tag.Value)
		}

		if aws.StringValue(instance.InstanceType) != "" {
			instanceType = aws.StringValue(instance.InstanceType)
		}

		if instanceName != "" && instanceType != "" {
			break
		}
	}

	if instanceType == "" {
		return fail.InconsistentError(nil, "error recovering instance type of Host %s", hostLabel)
	}

	var subnets []IPInSubnet

	for _, ni := range instance.NetworkInterfaces {
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

	ahf.Networking.IPv4Addresses = ip4bynetid
	ahf.Networking.IPv6Addresses = make(map[string]string)
	ahf.Networking.SubnetsByID = subnetnamebyid
	ahf.Networking.SubnetsByName = subnetidbyname
	if ahf.Networking.PublicIPv4 == "" {
		ahf.Networking.PublicIPv4 = ipv4
	}

	sizing := s.fromMachineTypeToHostEffectiveSizing(instanceType)

	ahf.Sizing.Cores = sizing.Cores
	ahf.Sizing.RAMSize = sizing.RAMSize
	ahf.Sizing.DiskSize = sizing.DiskSize

	ahf.Core.Name = instanceName

	if !ahf.OK() {
		logrus.Warnf("[TRACE] Unexpected host status: %s", spew.Sdump(ahf))
	}

	return nil
}

//func (s stack) inspectReservations(ahf *abstract.HostFull, hostRef string, reservation *ec2.Reservation) (xerr fail.Error) {
//	instanceName := ""
//	instanceType := ""
//
//	for _, i := range reservation.Instances {
//		if ahf.Core.LastState, xerr = toHostState(i.State); xerr != nil {
//			return xerr
//		}
//
//		for _, tag := range i.Tags {
//			if tag != nil {
//				if aws.StringValue(tag.Key) == "Name" || aws.StringValue(tag.Key) == "tag:Name" {
//					if aws.StringValue(tag.Value) != "" {
//						instanceName = aws.StringValue(tag.Value)
//						break
//					}
//				}
//			}
//		}
//
//		if aws.StringValue(i.InstanceType) != "" {
//			instanceType = aws.StringValue(i.InstanceType)
//			break
//		}
//	}
//
//	if instanceType == "" {
//		return fail.NewError(nil, "error recovering instance type of %s", hostRef)
//	}
//
//	var subnets []IPInSubnet
//
//	for _, i := range reservation.Instances {
//		for _, ni := range i.NetworkInterfaces {
//			newSubnet := IPInSubnet{
//				Name: getTagOfSubnet(s.EC2Service, ni.SubnetId, "Name"),
//				ID:   aws.StringValue(ni.SubnetId),
//				IP:   aws.StringValue(ni.PrivateIpAddress),
//			}
//
//			if ni.Association != nil {
//				if ni.Association.PublicIp != nil {
//					newSubnet.PublicIP = aws.StringValue(ni.Association.PublicIp)
//				}
//			}
//
//			subnets = append(subnets, newSubnet)
//		}
//	}
//
//	ip4bynetid := make(map[string]string)
//	subnetnamebyid := make(map[string]string)
//	subnetidbyname := make(map[string]string)
//
//	ipv4 := ""
//	for _, rn := range subnets {
//		ip4bynetid[rn.ID] = rn.IP
//		subnetnamebyid[rn.ID] = rn.Name
//		subnetidbyname[rn.Name] = rn.ID
//		if rn.PublicIP != "" {
//			ipv4 = rn.PublicIP
//		}
//	}
//
//	ahf.Networking.IPv4Addresses = ip4bynetid
//	ahf.Networking.IPv6Addresses = make(map[string]string)
//	ahf.Networking.SubnetsByID = subnetnamebyid
//	ahf.Networking.SubnetsByName = subnetidbyname
//	if ahf.Networking.PublicIPv4 == "" {
//		ahf.Networking.PublicIPv4 = ipv4
//	}
//
//	sizing := s.fromMachineTypeToHostEffectiveSizing(instanceType)
//
//	ahf.Sizing.Cores = sizing.Cores
//	ahf.Sizing.RAMSize = sizing.RAMSize
//	ahf.Sizing.DiskSize = sizing.DiskSize
//
//	ahf.Core.Name = instanceName
//
//	if !ahf.OK() {
//		logrus.Warnf("[TRACE] Unexpected host status: %s", spew.Sdump(ahf))
//	}
//
//	return nil
//}
//

func (s stack) fromMachineTypeToHostEffectiveSizing(machineType string) abstract.HostEffectiveSizing {
	nullSizing := abstract.HostEffectiveSizing{}

	templates, xerr := s.ListTemplates()
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
	query := ec2.DescribeSubnetsInput{
		SubnetIds: []*string{SubnetId},
	}
	var resp *ec2.DescribeSubnetsOutput
	xerr := stacks.RetryableRemoteCall(
		func() (err error) {
			resp, err = EC2Service.DescribeSubnets(&query)
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return aws.StringValue(SubnetId)
	}

	if len(resp.Subnets) > 0 {
		first := resp.Subnets[0]
		for _, tag := range first.Tags {
			if aws.StringValue(tag.Key) == s {
				return aws.StringValue(tag.Value)
			}
		}
	}

	return aws.StringValue(SubnetId)
}

// InspectHostByName returns host information by its name
func (s stack) InspectHostByName(name string) (_ *abstract.HostFull, xerr fail.Error) {
	nullAHF := abstract.NewHostFull()
	if s.IsNull() {
		return nullAHF, fail.InvalidInstanceError()
	}
	if name == "" {
		return nullAHF, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "('%s')", name).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&xerr)

	resp, xerr := s.rpcDescribeInstanceByName(aws.String(name))
	if xerr != nil {
		return nullAHF, xerr
	}
	ahf := abstract.NewHostFull()
	return ahf, s.inspectInstance(ahf, "'"+name+"'", resp)
}

// GetHostState returns the current state of the host
func (s stack) GetHostState(hostParam stacks.HostParameter) (_ hoststate.Enum, xerr fail.Error) {
	if s.IsNull() {
		return hoststate.UNKNOWN, fail.InvalidInstanceError()
	}

	host, xerr := s.InspectHost(hostParam)
	if xerr != nil {
		return hoststate.ERROR, xerr
	}

	return host.Core.LastState, nil
}

// ListHosts returns a list of hosts
func (s stack) ListHosts(details bool) (hosts abstract.HostList, xerr fail.Error) {
	nullList := abstract.HostList{}
	if s.IsNull() {
		return nullList, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(details=%v)", details).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&xerr)

	resp, xerr := s.rpcDescribeInstances(nil)
	if xerr != nil {
		return nullList, xerr
	}

	hosts = abstract.HostList{}
	for _, instance := range resp {
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

	return hosts, nil
}

// DeleteHost deletes a host
func (s stack) DeleteHost(hostParam stacks.HostParameter) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&xerr)

	ips, xerr := s.rpcDescribeAddresses([]*string{aws.String(ahf.Core.ID)})
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
		default:
			return xerr
		}
	}
	var errors []error
	for _, ip := range ips {
		if derr := s.rpcReleaseAddress(ip.AllocationId); derr != nil {
			errors = append(errors, fail.Wrap(derr, "cleaning up on failure, failed to delete IP address"))
		}
	}
	if len(errors) > 0 {
		return fail.NewErrorList(errors)
	}

	vm, xerr := s.rpcDescribeInstanceByID(aws.String(ahf.GetID()))
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// a host not found is considered as a successful deletion, continue
		default:
			return xerr
		}
	} else {
		// Get keypair and security group
		var (
			keyPairName     string
			attachedVolumes []string
			//secGroupId string
		)

		// register attached volumes
		for _, attVol := range vm.BlockDeviceMappings {
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

		keyPairName = aws.StringValue(vm.KeyName)
		//if len(inst.SecurityGroups) > 0 {
		//	sg := inst.SecurityGroups[0]
		//	secGroupId = aws.StringValue(sg.GroupId)
		//}

		// Terminate instance
		if xerr = s.rpcTerminateInstance(aws.String(ahf.GetID())); xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// continue
			default:
				return xerr
			}
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
			// FIXME: parallelize ?
			xerr = stacks.RetryableRemoteCall(
				func() error {
					_, err := s.EC2Service.DeleteVolume(&ec2.DeleteVolumeInput{
						VolumeId: aws.String(volume),
					})
					return err
				},
				normalizeError,
			)
			if xerr != nil {
				logrus.Warnf("problem cleaning up, deleting volume %s", volume)
			}
		}

		//// Remove security group
		//if secGroupId != "" {
		//	_, err = s.EC2Service.DeleteSecurityGroup(&ec2.DeleteSecurityGroupInput{
		//		GroupId: aws.String(secGroupId),
		//	})
		//	if err != nil {
		//		return fail.Wrap(err, "error deleting security group")
		//	}
		//} else {
		//	logrus.Warnf("security group %s for host '%s' not found", secGroupId, hostRef)
		//}

		// Remove keypair
		if keyPairName != "" {
			xerr = stacks.RetryableRemoteCall(
				func() error {
					_, err := s.EC2Service.DeleteKeyPair(&ec2.DeleteKeyPairInput{
						KeyName: aws.String(keyPairName),
					})
					return err
				},
				normalizeError,
			)
			if xerr != nil {
				return fail.Wrap(xerr, "error deleting keypair")
			}
		} else {
			logrus.Warnf("keypair '%s' for host '%s' not found", keyPairName, ahf.GetID())
		}
	}

	return nil
}

// StopHost stops a running host
func (s stack) StopHost(hostParam stacks.HostParameter) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&xerr)

	xerr = stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.StopInstances(&ec2.StopInstancesInput{
				Force:       aws.Bool(true),
				InstanceIds: []*string{aws.String(ahf.Core.ID)},
			})
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return xerr
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
func (s stack) StartHost(hostParam stacks.HostParameter) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&xerr)

	xerr = stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.StartInstances(&ec2.StartInstancesInput{
				InstanceIds: []*string{aws.String(ahf.Core.ID)},
			})
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return xerr
	}

	retryErr := retry.WhileUnsuccessful(
		func() error {
			hostTmp, innerErr := s.InspectHost(ahf.Core.ID)
			if innerErr != nil {
				return innerErr
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
func (s stack) RebootHost(hostParam stacks.HostParameter) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&xerr)

	xerr = stacks.RetryableRemoteCall(
		func() error {
			_, err := s.EC2Service.RebootInstances(&ec2.RebootInstancesInput{
				InstanceIds: []*string{aws.String(ahf.Core.ID)},
			})
			return err
		},
		normalizeError,
	)
	if xerr != nil {
		return xerr
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
func (s stack) ResizeHost(hostParam stacks.HostParameter, request abstract.HostSizingRequirements) (*abstract.HostFull, fail.Error) {
	nullAHF := abstract.NewHostFull()
	if s.IsNull() {
		return nullAHF, fail.InvalidInstanceError()
	}

	return nullAHF, fail.NotImplementedError("ResizeHost() not implemented yet") // FIXME: Technical debt
}

// BindSecurityGroupToHost ...
func (s stack) BindSecurityGroupToHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}

	return fail.NotImplementedError("not yet implemented")
}

// UnbindSecurityGroupFromHost ...
func (s stack) UnbindSecurityGroupFromHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}

	return fail.NotImplementedError("not yet implemented")
}
