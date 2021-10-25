/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
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
		return fail.InvalidParameterCannotBeNilError("keypair")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%v)", keypair).WithStopwatch().Entering().Exiting()
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
func (s stack) InspectImage(id string) (_ abstract.Image, xerr fail.Error) {
	nullAI := abstract.Image{}
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

	return toAbstractImage(*resp), nil
}

// InspectTemplate loads information about a template stored in AWS
func (s stack) InspectTemplate(id string) (template abstract.HostTemplate, xerr fail.Error) {
	nullAHT := abstract.HostTemplate{}
	if s.IsNull() {
		return nullAHT, fail.InvalidInstanceError()
	}
	if id == "" {
		return nullAHT, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&xerr)

	resp, xerr := s.rpcDescribeInstanceTypeByID(aws.String(id))
	if xerr != nil {
		return nullAHT, xerr
	}

	return toAbstractHostTemplate(*resp), nil
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

	// FIXME: AWS CentOS AND Others, and HARCODED providers
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

	resp, xerr := s.rpcDescribeInstanceTypes(nil)
	if xerr != nil {
		return emptySlice, xerr
	}

	// sort response on Network Performance to potentially have cheaper choices first
	sort.Slice(
		resp, func(i, j int) bool {
			return aws.StringValue(resp[i].NetworkInfo.NetworkPerformance) < aws.StringValue(resp[j].NetworkInfo.NetworkPerformance)
		},
	)

	// converts response from AWS to abstract
	list := make([]abstract.HostTemplate, 0, len(resp))
	for _, v := range resp {
		list = append(list, toAbstractHostTemplate(*v))
	}

	return list, nil
}

func toAbstractHostTemplate(in ec2.InstanceTypeInfo) abstract.HostTemplate {
	out := abstract.HostTemplate{
		ID:   aws.StringValue(in.InstanceType),
		Name: aws.StringValue(in.InstanceType),
	}
	if in.VCpuInfo != nil {
		out.Cores = int(aws.Int64Value(in.VCpuInfo.DefaultCores))
	}
	if in.MemoryInfo != nil {
		out.RAMSize = float32(aws.Int64Value(in.MemoryInfo.SizeInMiB) / 1024.0)
	}
	if in.ProcessorInfo != nil {
		out.CPUFreq =
			float32(aws.Float64Value(in.ProcessorInfo.SustainedClockSpeedInGhz))
	}
	if in.InstanceStorageInfo != nil {
		out.DiskSize = int(aws.Int64Value(in.InstanceStorageInfo.TotalSizeInGB))
	}
	if in.GpuInfo != nil && len(in.GpuInfo.Gpus) > 0 {
		out.GPUNumber = len(in.GpuInfo.Gpus)
		out.GPUType = aws.StringValue(in.GpuInfo.Gpus[0].Manufacturer) + " " + aws.StringValue(in.GpuInfo.Gpus[0].Name)
	}
	return out
}

// WaitHostReady waits until a host achieves ready state
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

			if hostTmp.CurrentState == hoststate.Error {
				innerXErr = retry.StopRetryError(
					fail.NewError("last state: %s", hostTmp.CurrentState.String()),
					"error waiting for host in ready state",
				)
				return innerXErr
			}

			if hostTmp.CurrentState != hoststate.Started {
				innerXErr = fail.NewError("not in ready state (current state: %s)", ahf.CurrentState.String())
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
			return nullAHC, fail.Wrap(fail.Cause(retryErr), "stopping retries")
		case *retry.ErrTimeout:
			return nullAHC, fail.Wrap(
				fail.Cause(retryErr), "timeout waiting to get host '%s' information after %v", ahf.GetID(), timeout,
			)
		default:
			return nullAHC, retryErr
		}
	}
	return ahf.Core, nil
}

// CreateHost creates a host
func (s stack) CreateHost(request abstract.HostRequest) (ahf *abstract.HostFull, userData *userdata.Content, ferr fail.Error) {
	nullAHF := abstract.NewHostFull()
	nullUDC := userdata.NewContent()
	if s.IsNull() {
		return nullAHF, nullUDC, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%v)", request).WithStopwatch().Entering().Exiting()
	defer fail.OnPanic(&ferr)
	defer fail.OnExitTraceError(&ferr)

	resourceName := request.ResourceName
	subnets := request.Subnets
	// hostMustHavePublicIP := request.PublicIP

	if len(subnets) == 0 {
		return nullAHF, nullUDC, fail.InvalidRequestError(
			"the Host '%s' must be on at least one Subnet (even if public)", resourceName,
		)
	}

	// If no credentials (KeyPair and/or Password) are supplied create ones
	var xerr fail.Error
	if xerr = stacks.ProvideCredentialsIfNeeded(&request); xerr != nil {
		return nullAHF, nullUDC, fail.Wrap(xerr, "failed to provide credentials for Host")
	}
	keyPairName := request.KeyPair.Name

	// The default Subnet is the first of the provided list, by convention
	defaultSubnet, defaultSubnetID := func() (*abstract.Subnet, string) {
		if len(request.Subnets) == 0 {
			return nil, ""
		}
		return request.Subnets[0], request.Subnets[0].ID
	}()
	publicIP := request.IsGateway || request.Single

	if defaultSubnet == nil {
		if !request.PublicIP {
			return nullAHF, nullUDC, abstract.ResourceInvalidRequestError(
				"host creation", "cannot create a host without public IP or attached network",
			)
		}
		return nullAHF, nullUDC, abstract.ResourceInvalidRequestError(
			"host creation", "cannot create a host without default subnet",
		)
	}

	// --- prepares data structures for Provider usage ---

	// Constructs userdata content
	userData = userdata.NewContent()
	if xerr = userData.Prepare(*s.Config, request, defaultSubnet.CIDR, ""); xerr != nil {
		logrus.Debugf(strprocess.Capitalize(fmt.Sprintf("failed to prepare user data content: %+v", xerr)))
		return nullAHF, nullUDC, fail.Wrap(xerr, "failed to prepare user data content")
	}

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

	// --- Initializes resources.IPAddress ---

	ahf = abstract.NewHostFull()
	ahf.Core.PrivateKey = userData.FirstPrivateKey // Add initial PrivateKey to Host description
	ahf.Core.Password = request.Password

	ahf.Networking.DefaultSubnetID = defaultSubnetID
	ahf.Networking.IsGateway = request.IsGateway

	// Adds IPAddress property SizingV1
	ahf.Sizing = converters.HostTemplateToHostEffectiveSizing(template)

	// Sets provider parameters to create ahf
	userDataPhase1, xerr := userData.Generate(userdata.PHASE1_INIT)
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}

	// import keypair on provider side
	keypair := abstract.KeyPair{
		Name:       keyPairName,
		PublicKey:  userData.FirstPublicKey,
		PrivateKey: userData.FirstPrivateKey,
	}
	if xerr = s.ImportKeyPair(&keypair); xerr != nil {
		return nullAHF, nullUDC, xerr
	}

	// --- query provider for ahf creation ---

	logrus.Debugf("requesting host resource creation...")

	// Retry creation until success, for 10 minutes
	xerr = retry.WhileUnsuccessful(
		func() error {
			var (
				server    *abstract.HostCore
				innerXErr fail.Error
			)
			if request.Preemptible {
				server, innerXErr = s.buildAwsSpotMachine(
					keyPairName, request.ResourceName, rim.ID, s.AwsConfig.Zone, defaultSubnet.ID,
					string(userDataPhase1), publicIP, template,
				)
			} else {
				server, innerXErr = s.buildAwsMachine(
					keyPairName, request.ResourceName, rim.ID, s.AwsConfig.Zone, defaultSubnet.ID,
					string(userDataPhase1), publicIP, template,
				)
			}
			if innerXErr != nil {
				captured := normalizeError(innerXErr)

				switch captured.(type) {
				case *fail.ErrNotFound, *fail.ErrDuplicate, *fail.ErrInvalidRequest, *fail.ErrNotAuthenticated, *fail.ErrForbidden, *fail.ErrOverflow, *fail.ErrSyntax, *fail.ErrInconsistent, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent, *fail.ErrInvalidParameter, *fail.ErrRuntimePanic: // Do not retry if it's going to fail anyway
					return retry.StopRetryError(captured)
				default:
					logrus.Warnf("error creating Host: %+v", captured)

					if server != nil && server.ID != "" {
						if derr := s.DeleteHost(server.ID); derr != nil {
							_ = innerXErr.AddConsequence(
								fail.Wrap(
									derr, "cleaning up on failure, failed to delete Host '%s'", server.Name,
								),
							)
						}
					}
					return captured
				}
			}

			if server == nil {
				return fail.NewError(nil, "failed to create server")
			}

			ahf.Core.ID = server.ID
			ahf.Core.Name = server.Name

			// Wait until IPAddress is ready, not just until the build is started
			if _, innerXErr = s.WaitHostReady(ahf, temporal.GetLongOperationTimeout()); innerXErr != nil {
				if derr := s.DeleteHost(ahf.Core.ID); derr != nil {
					_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Host"))
				}
				return innerXErr
			}

			return nil
		},
		temporal.GetDefaultDelay(),
		temporal.GetLongOperationTimeout(),
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry:
			return nullAHF, nullUDC, fail.Wrap(fail.Cause(xerr), "failed to create Host, stopping retries")
		case *fail.ErrTimeout:
			return nullAHF, nullUDC, fail.Wrap(fail.Cause(xerr), "failed to create Host because of timeout")
		default:
			return nullAHF, nullUDC, xerr
		}
	}

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

	if !ahf.OK() {
		logrus.Warnf("Missing data in ahf: %v", ahf)
	}

	return ahf, userData, nil
}

func (s stack) buildAwsSpotMachine(
	keypairName string,
	name string,
	imageID string,
	zone string,
	netID string,
	data string,
	publicIP bool,
	template abstract.HostTemplate,
) (*abstract.HostCore, fail.Error) {

	resp, xerr := s.rpcDescribeSpotPriceHistory(aws.String(zone), aws.String(template.ID))
	if xerr != nil {
		return nil, xerr
	}

	lastPrice := resp[len(resp)-1]
	logrus.Warnf("Last price detected %s", aws.StringValue(lastPrice.SpotPrice))

	instance, xerr := s.rpcRequestSpotInstance(
		lastPrice.SpotPrice, aws.String(zone), aws.String(netID), aws.Bool(publicIP), aws.String(template.ID),
		aws.String(imageID), aws.String(keypairName), []byte(data),
	)
	if xerr != nil {
		return nil, xerr
	}

	// FIXME: Listen to result.SpotInstanceRequests[0].GetState

	host := abstract.HostCore{
		ID:   aws.StringValue(instance.InstanceId),
		Name: name,
	}
	return &host, nil
}

func (s stack) buildAwsMachine(
	keypairName string,
	name string,
	imageID string,
	zone string,
	subnetID string,
	data string,
	publicIP bool,
	template abstract.HostTemplate,
) (*abstract.HostCore, fail.Error) {

	instance, xerr := s.rpcRunInstance(
		aws.String(name), aws.String(zone), aws.String(subnetID), aws.String(template.ID), aws.String(imageID),
		aws.String(keypairName), aws.Bool(publicIP), []byte(data),
	)
	if xerr != nil {
		return nil, xerr
	}

	hostCore := abstract.HostCore{
		ID:   aws.StringValue(instance.InstanceId),
		Name: name,
	}
	return &hostCore, nil
}

// ClearHostStartupScript clears the userdata startup script for Host instance (metadata service)
// FIXME: see if anything is needed (does nothing for now)
func (s stack) ClearHostStartupScript(hostParam stacks.HostParameter) fail.Error {
	return nil
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
			Name: s.getTagOfSubnet(ni.SubnetId, tagNameLabel),
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

	sizing, xerr := s.fromMachineTypeToHostEffectiveSizing(instanceType)
	if xerr != nil {
		return xerr
	}

	ahf.Sizing.Cores = sizing.Cores
	ahf.Sizing.RAMSize = sizing.RAMSize
	ahf.Sizing.DiskSize = sizing.DiskSize

	ahf.Core.Name = instanceName

	// Store template and image also in tags
	for _, tag := range instance.Tags {
		if tag != nil {
			ahf.Core.Tags[aws.StringValue(tag.Key)] = aws.StringValue(tag.Value)
		}
	}
	ahf.Core.Tags["Template"] = instanceType
	ahf.Core.Tags["Image"] = aws.StringValue(instance.ImageId)

	return nil
}

func (s stack) fromMachineTypeToHostEffectiveSizing(machineType string) (abstract.HostEffectiveSizing, fail.Error) {
	nullSizing := abstract.HostEffectiveSizing{}
	resp, xerr := s.rpcDescribeInstanceTypeByID(aws.String(machineType))
	if xerr != nil {
		return nullSizing, xerr
	}

	hs := converters.HostTemplateToHostEffectiveSizing(toAbstractHostTemplate(*resp))
	return *hs, nil
}

func (s stack) getTagOfSubnet(subnetID *string, str string) string {
	resp, xerr := s.rpcDescribeSubnetByID(subnetID)
	if xerr != nil {
		return aws.StringValue(subnetID)
	}

	for _, tag := range resp.Tags {
		if aws.StringValue(tag.Key) == str {
			return aws.StringValue(tag.Value)
		}
	}
	return aws.StringValue(subnetID)
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
		return hoststate.Unknown, fail.InvalidInstanceError()
	}

	host, xerr := s.InspectHost(hostParam)
	if xerr != nil {
		return hoststate.Error, xerr
	}

	return host.CurrentState, nil
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
			ahf.CurrentState, ahf.Core.LastState = state, state
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

// DeleteHost deletes a IPAddress
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

	vm, xerr := s.rpcDescribeInstanceByID(aws.String(ahf.GetID()))
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// a host not found is considered as a successful deletion, continue
			debug.IgnoreError(xerr)
		default:
			return xerr
		}
	}

	// Get keypair and security group
	var (
		keyPairName     string
		attachedVolumes []string
	)

	// inventory attached volumes
	for _, attVol := range vm.BlockDeviceMappings {
		if attVol != nil && attVol.Ebs != nil && attVol.Ebs.VolumeId != nil {
			volume := aws.StringValue(attVol.Ebs.VolumeId)
			if volume != "" {
				attachedVolumes = append(attachedVolumes, volume)
			}
		}
	}

	keyPairName = aws.StringValue(vm.KeyName)

	// Stop instance forcibly
	xerr = s.StopHost(ahf, false)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to stop Host '%s' with id '%s'", ahf.GetName(), ahf.GetID())
	}

	// Terminate instance
	xerr = s.rpcTerminateInstance(vm)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			debug.IgnoreError(xerr)
			// continue
		default:
			return xerr
		}
	}

	// Remove volumes if some remain, mark errors as warnings
	for _, volume := range attachedVolumes {
		// FIXME: parallelize ?
		xerr = stacks.RetryableRemoteCall(
			func() error {
				_, err := s.EC2Service.DeleteVolume(
					&ec2.DeleteVolumeInput{
						VolumeId: aws.String(volume),
					},
				)
				return err
			},
			normalizeError,
		)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// A missing volume is considered as a successful deletion
				debug.IgnoreError(xerr)
			default:
				logrus.Warnf("failed to delete volume %s", volume)
			}
		}
	}

	// Remove keypair
	if keyPairName != "" {
		xerr = s.rpcDeleteKeyPair(aws.String(keyPairName))
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// A missing keypair is considered as a successful deletion
				debug.IgnoreError(xerr)
			default:
				return fail.Wrap(xerr, "error deleting keypair '%s'", keyPairName)
			}
		}
	}

	return nil
}

// StopHost stops a running host
func (s stack) StopHost(hostParam stacks.HostParameter, gracefully bool) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&xerr)

	if xerr = s.rpcStopInstances([]*string{aws.String(ahf.Core.ID)}, aws.Bool(gracefully)); xerr != nil {
		return xerr
	}

	retryErr := retry.WhileUnsuccessful(
		func() error {
			hostTmp, err := s.InspectHost(ahf.Core.ID)
			if err != nil {
				return err
			}

			if hostTmp.CurrentState != hoststate.Stopped && hostTmp.CurrentState != hoststate.Terminated {
				return fail.NewError(
					"not in stopped or terminated state (current state: %s)", hostTmp.CurrentState.String(),
				)
			}
			return nil
		},
		temporal.GetDefaultDelay(),
		temporal.GetHostCleanupTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry:
			return fail.Wrap(fail.Cause(retryErr), "stopping retries")
		case *retry.ErrTimeout:
			return fail.Wrap(
				fail.Cause(retryErr), "timeout waiting to get host '%s' information after %v", hostRef,
				temporal.GetHostCleanupTimeout(),
			)
		default:
			return retryErr
		}
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

	xerr = s.rpcStartInstances([]*string{aws.String(ahf.Core.ID)})
	if xerr != nil {
		return xerr
	}

	retryErr := retry.WhileUnsuccessful(
		func() error {
			hostTmp, innerErr := s.InspectHost(ahf.Core.ID)
			if innerErr != nil {
				return innerErr
			}

			if hostTmp.CurrentState != hoststate.Started {
				return fail.NewError("not in started state (current state: %s)", hostTmp.CurrentState.String())
			}
			return nil
		},
		temporal.GetDefaultDelay(),
		temporal.GetHostCleanupTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry:
			return fail.Wrap(fail.Cause(retryErr), "stopping retries")
		case *retry.ErrTimeout:
			return fail.Wrap(
				fail.Cause(retryErr), "timeout waiting to get information of host '%s' after %v", hostRef,
				temporal.GetHostCleanupTimeout(),
			)
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

	if xerr = s.rpcRebootInstances([]*string{aws.String(ahf.Core.ID)}); xerr != nil {
		return xerr
	}

	retryErr := retry.WhileUnsuccessful(
		func() error {
			hostTmp, innerErr := s.InspectHost(ahf)
			if innerErr != nil {
				return innerErr
			}

			if hostTmp.CurrentState != hoststate.Started {
				return fail.NewError("not in started state (current state: %s)", hostTmp.CurrentState.String())
			}
			return nil
		},
		temporal.GetDefaultDelay(),
		2*temporal.GetHostCleanupTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry:
			return fail.Wrap(fail.Cause(retryErr), "stopping retries")
		case *retry.ErrTimeout:
			return fail.Wrap(
				fail.Cause(retryErr), "timeout waiting to get host '%s' information after %v", hostRef,
				temporal.GetHostCleanupTimeout(),
			)
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
// Returns:
// - *fail.ErrNotFound if the IPAddress is not found
func (s stack) BindSecurityGroupToHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, _, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}
	if !ahf.IsConsistent() {
		if ahf, xerr = s.InspectHost(ahf); xerr != nil {
			return xerr
		}
	}
	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam) // nolint
	if xerr != nil {
		return xerr
	}
	if !asg.IsConsistent() {
		if asg, xerr = s.InspectSecurityGroup(asg); xerr != nil {
			return xerr
		}
	}

	resp, xerr := s.rpcDescribeInstanceByID(aws.String(ahf.GetID()))
	if xerr != nil {
		return xerr
	}

	sgs := make([]*string, 0, len(resp.SecurityGroups)+1)
	sgs = append(sgs, aws.String(asg.ID))
	for _, v := range resp.SecurityGroups {
		switch aws.StringValue(v.GroupId) {
		case asg.ID:
			continue
		default:
			sgs = append(sgs, v.GroupId)
		}
	}

	// If count of Security Groups does not change, do nothing (saves a remote call)
	if len(sgs) == len(resp.SecurityGroups) {
		return nil
	}
	if xerr = s.rpcModifyInstanceSecurityGroups(aws.String(ahf.GetID()), sgs); xerr != nil {
		return xerr
	}

	return nil
}

// UnbindSecurityGroupFromHost ...
// Returns:
// - nil means success
// - *fail.ErrNotFound if the IPAddress or the Security Group ID cannot be identified
func (s stack) UnbindSecurityGroupFromHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, _, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}
	if !ahf.IsConsistent() {
		ahf, xerr = s.InspectHost(ahf)
		if xerr != nil {
			return xerr
		}
	}
	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam) // nolint
	if xerr != nil {
		return xerr
	}

	if !asg.IsComplete() {
		asg, xerr = s.InspectSecurityGroup(asg)
		if xerr != nil {
			return xerr
		}
	}

	// query the instance to get its current Security Groups
	resp, xerr := s.rpcDescribeInstanceByID(aws.String(ahf.GetID()))
	if xerr != nil {
		return xerr
	}

	sgs := make([]*string, 0, len(resp.SecurityGroups)+1)

	// If there is one last Security Group bound to IPAddress, restore bond to default SecurityGroup before removing
	if len(resp.SecurityGroups) == 1 && aws.StringValue(resp.SecurityGroups[0].GroupId) == asg.ID {
		defaultSG := abstract.NewSecurityGroup()
		defaultSG.Name = s.GetDefaultSecurityGroupName()
		defaultSG.Network = asg.Network
		defaultSG, xerr := s.InspectSecurityGroup(defaultSG)
		if xerr != nil {
			return xerr
		}
		sgs = append(sgs, aws.String(defaultSG.ID))
	}

	// Filter out the Security Group to remove
	for _, v := range resp.SecurityGroups {
		switch aws.StringValue(v.GroupId) {
		case asg.ID:
			continue
		default:
			sgs = append(sgs, v.GroupId)
		}
	}
	// If the Security Group asked for unbind is not present, do nothing (saves one remote call)
	if len(sgs) == len(resp.SecurityGroups) {
		return nil
	}

	return s.rpcModifyInstanceSecurityGroups(aws.String(ahf.GetID()), sgs)
}
