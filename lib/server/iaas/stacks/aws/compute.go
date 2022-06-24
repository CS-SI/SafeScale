/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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
	"context"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	mapset "github.com/deckarep/golang-set"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/operations/converters"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

// CreateKeyPair creates a keypair and upload it to AWS
func (s stack) CreateKeyPair(ctx context.Context, name string) (_ *abstract.KeyPair, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "('%s')", name).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&ferr)

	keypair, xerr := abstract.NewKeyPair(name)
	if xerr != nil {
		return nil, xerr
	}

	if xerr = s.rpcImportKeyPair(ctx, aws.String(keypair.Name), []byte(keypair.PublicKey)); xerr != nil {
		return nil, xerr
	}
	return keypair, nil
}

// ImportKeyPair imports an existing resources.KeyPair to AWS (not in the interface yet, but will come soon)
func (s stack) ImportKeyPair(ctx context.Context, keypair *abstract.KeyPair) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if keypair == nil {
		return fail.InvalidParameterCannotBeNilError("keypair")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%v)", keypair).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&ferr)

	return s.rpcImportKeyPair(ctx, aws.String(keypair.Name), []byte(keypair.PublicKey))
}

// InspectKeyPair loads a keypair from AWS
// Note: the private key is not stored by AWS...
func (s stack) InspectKeyPair(ctx context.Context, id string) (_ *abstract.KeyPair, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).
		WithStopwatch().
		Entering().
		Exiting()
	defer fail.OnExitTraceError(&ferr)

	resp, xerr := s.rpcDescribeKeyPairByID(ctx, aws.String(id))
	if xerr != nil {
		return nil, xerr
	}

	out := toAbstractKeyPair(*resp)
	return out, nil
}

func toAbstractKeyPair(in ec2.KeyPairInfo) *abstract.KeyPair {
	out := &abstract.KeyPair{}
	out.ID = aws.StringValue(in.KeyPairId)
	out.Name = aws.StringValue(in.KeyName)
	out.PublicKey = aws.StringValue(in.KeyFingerprint)
	return out
}

// ListKeyPairs lists keypairs stored in AWS
func (s stack) ListKeyPairs(ctx context.Context) (_ []*abstract.KeyPair, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute")).
		WithStopwatch().
		Entering().
		Exiting()
	defer fail.OnExitTraceError(&ferr)

	resp, xerr := s.rpcDescribeKeyPairs(ctx, nil)
	if xerr != nil {
		return nil, xerr
	}
	var keys []*abstract.KeyPair
	for _, kp := range resp {
		keys = append(keys, toAbstractKeyPair(*kp))
	}
	return keys, nil
}

// DeleteKeyPair deletes a keypair from AWS
func (s stack) DeleteKeyPair(ctx context.Context, id string) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&ferr)

	return s.rpcDeleteKeyPair(ctx, aws.String(id))
}

// ListAvailabilityZones lists AWS availability zones available
func (s stack) ListAvailabilityZones(ctx context.Context) (_ map[string]bool, ferr fail.Error) {
	emptyMap := map[string]bool{}
	if valid.IsNil(s) {
		return emptyMap, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute")).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&ferr)

	resp, xerr := s.rpcDescribeAvailabilityZones(ctx, nil)
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
func (s stack) ListRegions(ctx context.Context) (_ []string, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute")).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&ferr)

	resp, xerr := s.rpcDescribeRegions(ctx, nil)
	if xerr != nil {
		return nil, xerr
	}
	if len(resp) > 0 {
		regions := make([]string, 0, len(resp))
		for _, region := range resp {
			regions = append(regions, aws.StringValue(region.RegionName))
		}
		return regions, nil
	}

	return []string{}, nil
}

// InspectImage loads information about an image stored in AWS
func (s stack) InspectImage(ctx context.Context, id string) (_ *abstract.Image, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&ferr)

	resp, xerr := s.rpcDescribeImageByID(ctx, aws.String(id))
	if xerr != nil {
		return nil, xerr
	}

	return toAbstractImage(*resp), nil
}

// InspectTemplate loads information about a template stored in AWS
func (s stack) InspectTemplate(ctx context.Context, id string) (template *abstract.HostTemplate, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&ferr)

	resp, xerr := s.rpcDescribeInstanceTypeByID(ctx, aws.String(id))
	if xerr != nil {
		return nil, xerr
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
		{
			Name:   aws.String("is-public"),
			Values: []*string{aws.String("true")},
		},
	}

	return filters
}

// createFilters ...
func filterOwners(s stack) []*ec2.Filter {
	var owners []*string

	ownerSet := mapset.NewSet()
	ownerSet.Add("099720109477") // Ubuntu
	ownerSet.Add("013116697141") // Fedora
	ownerSet.Add("379101102735") // Debian
	ownerSet.Add("125523088429") // CentOS 8
	ownerSet.Add("161831738826") // Centos 7 with ENA
	ownerSet.Add("057448758665") // Centos 7
	ownerSet.Add("679593333241") // Centos 6 AND Others
	// ownerSet.Add("595879546273") // CoreOS
	// ownerSet.Add("136693071363") // More Debian

	for _, ow := range s.AwsConfig.Owners {
		ownerSet.Add(ow)
	}

	for item := range ownerSet.Iter() {
		ao, ok := item.(string)
		if !ok {
			continue
		}
		matched, err := regexp.Match(`([0-9]){12}`, []byte(ao)) // nolint
		if err != nil {
			continue
		}
		if !matched {
			continue
		}

		owners = append(owners, aws.String(ao))
	}

	filters := &ec2.Filter{
		Name:   aws.String("owner-id"),
		Values: owners,
	}

	return []*ec2.Filter{filters}
}

// ListImages lists available image
func (s stack) ListImages(ctx context.Context, all bool) (_ []*abstract.Image, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute")).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&ferr)

	resp, xerr := s.rpcDescribeImages(ctx, nil)
	if xerr != nil {
		return nil, xerr
	}
	if len(resp) > 0 {
		images := make([]*abstract.Image, 0, len(resp))
		for _, image := range resp {
			if image != nil {
				if !aws.BoolValue(image.EnaSupport) {
					logrus.Debug("ENA filtering does NOT actually work!")
					continue
				}

				images = append(images, toAbstractImage(*image))
			}
		}
		return images, nil
	}

	return []*abstract.Image{}, nil
}

func toAbstractImage(in ec2.Image) *abstract.Image {
	return &abstract.Image{
		ID:          aws.StringValue(in.ImageId),
		Name:        aws.StringValue(in.Name),
		Description: aws.StringValue(in.Description),
		StorageType: aws.StringValue(in.RootDeviceType),
	}
}

// ListTemplates lists templates stored in AWS
func (s stack) ListTemplates(ctx context.Context, all bool) (templates []*abstract.HostTemplate, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute")).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&ferr)

	var resp []*ec2.InstanceTypeInfo
	unfilteredResp, xerr := s.rpcDescribeInstanceTypes(ctx, nil)
	if xerr != nil {
		return nil, xerr
	}

	// list only the resources actually available in our AZ
	under, xerr := s.rpcDescribeInstanceTypeOfferings(ctx, aws.String(s.AwsConfig.Zone))
	if xerr != nil {
		return nil, xerr
	}

	// put those into a set
	availableTemplateNames := mapset.NewSet()
	for _, item := range under.InstanceTypeOfferings {
		availableTemplateNames.Add(aws.StringValue(item.InstanceType))
	}

	// not available resources are filtered out
	for _, item := range unfilteredResp {
		if availableTemplateNames.Contains(aws.StringValue(item.InstanceType)) {
			resp = append(resp, item)
		}
	}

	// sort response on Network Performance to potentially have cheaper choices first
	sort.Slice(
		resp, func(i, j int) bool {
			return aws.StringValue(resp[i].NetworkInfo.NetworkPerformance) < aws.StringValue(resp[j].NetworkInfo.NetworkPerformance)
		},
	)

	// converts response from AWS to abstract
	list := make([]*abstract.HostTemplate, 0, len(resp))
	for _, v := range resp {
		list = append(list, toAbstractHostTemplate(*v))
	}

	return list, nil
}

func toAbstractHostTemplate(in ec2.InstanceTypeInfo) *abstract.HostTemplate {
	out := &abstract.HostTemplate{
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
func (s stack) WaitHostReady(ctx context.Context, hostParam stacks.HostParameter, timeout time.Duration) (_ *abstract.HostCore, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return nil, xerr
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s, %v)", hostRef, timeout).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&ferr)

	retryErr := retry.WhileUnsuccessful(
		func() error {
			hostTmp, innerXErr := s.InspectHost(ctx, ahf)
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
		temporal.DefaultDelay(),
		timeout,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry:
			return nil, fail.Wrap(fail.Cause(retryErr), "stopping retries")
		case *retry.ErrTimeout:
			return nil, fail.Wrap(
				fail.Cause(retryErr), "timeout waiting to get host '%s' information after %v", ahf.GetID(), timeout,
			)
		default:
			return nil, retryErr
		}
	}
	return ahf.Core, nil
}

// CreateHost creates a host
func (s stack) CreateHost(ctx context.Context, request abstract.HostRequest) (ahf *abstract.HostFull, userData *userdata.Content, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(s) {
		return nil, nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%v)", request).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&ferr)

	resourceName := request.ResourceName
	subnets := request.Subnets
	// hostMustHavePublicIP := request.PublicIP

	if len(subnets) == 0 {
		return nil, nil, fail.InvalidRequestError(
			"the Host '%s' must be on at least one Subnet (even if public)", resourceName,
		)
	}

	// If no credentials (KeyPair and/or Password) are supplied create ones
	var xerr fail.Error
	if xerr = stacks.ProvideCredentialsIfNeeded(&request); xerr != nil {
		return nil, nil, fail.Wrap(xerr, "failed to provide credentials for Host")
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
			return nil, nil, abstract.ResourceInvalidRequestError(
				"host creation", "cannot create a host without public IP or attached network",
			)
		}
		return nil, nil, abstract.ResourceInvalidRequestError(
			"host creation", "cannot create a host without default subnet",
		)
	}

	// --- prepares data structures for Provider usage ---

	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, nil, xerr
	}

	// Constructs userdata content
	userData = userdata.NewContent()
	if xerr = userData.Prepare(*s.Config, request, defaultSubnet.CIDR, "", timings); xerr != nil {
		logrus.Debugf(strprocess.Capitalize(fmt.Sprintf("failed to prepare user data content: %+v", xerr)))
		return nil, nil, fail.Wrap(xerr, "failed to prepare user data content")
	}

	template, xerr := s.InspectTemplate(ctx, request.TemplateID)
	if xerr != nil {
		return nil, nil, fail.Wrap(xerr, "failed to get host template '%s'", request.TemplateID)
	}

	rim, xerr := s.InspectImage(ctx, request.ImageID)
	if xerr != nil {
		return nil, nil, fail.Wrap(xerr, "failed to get image '%s'", request.ImageID)
	}

	diskSize := request.DiskSize
	if diskSize > template.DiskSize {
		diskSize = request.DiskSize
	}

	if int(rim.DiskSize) > diskSize {
		diskSize = int(rim.DiskSize)
	}

	if diskSize == 0 {
		// Determines appropriate disk size
		// if still zero here, we take template.DiskSize
		if template.DiskSize != 0 {
			diskSize = template.DiskSize
		} else {
			if template.Cores < 16 { // nolint
				template.DiskSize = 100
			} else if template.Cores < 32 {
				template.DiskSize = 200
			} else {
				template.DiskSize = 400
			}
		}
	}

	if diskSize < 10 {
		diskSize = 10
	}

	logrus.Debugf("Selected template: '%s', '%s'", template.ID, template.Name)

	// Select usable availability zone, the first one in the list
	if s.AwsConfig.Zone == "" {
		azList, xerr := s.ListAvailabilityZones(ctx)
		if xerr != nil {
			return nil, nil, xerr
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
	ahf.Core.PrivateKey = userData.FirstPrivateKey // Add initial PrivateKey to Host description
	ahf.Core.Password = request.Password

	ahf.Networking.DefaultSubnetID = defaultSubnetID
	ahf.Networking.IsGateway = request.IsGateway

	// Adds Host property SizingV1
	ahf.Sizing = converters.HostTemplateToHostEffectiveSizing(*template)

	// Sets provider parameters to create ahf
	userDataPhase1, xerr := userData.Generate(userdata.PHASE1_INIT)
	if xerr != nil {
		return nil, nil, xerr
	}

	// import keypair on provider side
	keypair := abstract.KeyPair{
		Name:       keyPairName,
		PublicKey:  userData.FirstPublicKey,
		PrivateKey: userData.FirstPrivateKey,
	}
	if xerr = s.ImportKeyPair(ctx, &keypair); xerr != nil {
		return nil, nil, xerr
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
				server, innerXErr = s.buildAwsSpotMachine( // FIXME: Disk size
					ctx, keyPairName, request.ResourceName, rim.ID, s.AwsConfig.Zone, defaultSubnet.ID, diskSize,
					string(userDataPhase1), publicIP, *template,
				)
			} else {
				server, innerXErr = s.buildAwsMachine( // FIXME: Disk size
					ctx, keyPairName, request.ResourceName, rim.ID, s.AwsConfig.Zone, defaultSubnet.ID, diskSize,
					string(userDataPhase1), publicIP, *template,
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
						if derr := s.DeleteHost(ctx, server.ID); derr != nil {
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

			// Wait until Host is ready, not just until the build is started
			if _, innerXErr = s.WaitHostReady(ctx, ahf, timings.HostLongOperationTimeout()); innerXErr != nil {
				if derr := s.DeleteHost(ctx, ahf.Core.ID); derr != nil {
					_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Host"))
				}
				return innerXErr
			}

			return nil
		},
		timings.NormalDelay(),
		timings.HostLongOperationTimeout(),
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry, *fail.ErrNotFound, *fail.ErrDuplicate, *fail.ErrInvalidRequest, *fail.ErrNotAuthenticated, *fail.ErrForbidden, *fail.ErrOverflow, *fail.ErrSyntax, *fail.ErrInconsistent, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent, *fail.ErrInvalidParameter, *fail.ErrRuntimePanic: // Do not retry if it's going to fail anyway
			return nil, nil, fail.Wrap(fail.Cause(xerr), "failed to create Host, stopping retries")
		case *fail.ErrTimeout:
			return nil, nil, fail.Wrap(fail.Cause(xerr), "failed to create Host because of timeout")
		default:
			return nil, nil, xerr
		}
	}

	// Starting from here, delete host if exiting with error
	defer func() {
		if ferr != nil && !request.KeepOnFailure {
			logrus.Infof("Cleanup, deleting host '%s'", ahf.Core.Name)
			if derr := s.DeleteHost(ctx, ahf.Core.ID); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Host"))
				logrus.Warnf("Error deleting host in cleanup: %v", derr)
			}
		}
	}()

	if !ahf.OK() {
		logrus.Warnf("Missing data in ahf: %v", ahf)
	}

	return ahf, userData, nil
}

func (s stack) buildAwsSpotMachine(
	ctx context.Context,
	keypairName string,
	name string,
	imageID string,
	zone string,
	netID string,
	_ int,
	data string,
	publicIP bool,
	template abstract.HostTemplate,
) (*abstract.HostCore, fail.Error) {
	resp, xerr := s.rpcDescribeSpotPriceHistory(ctx, aws.String(zone), aws.String(template.ID))
	if xerr != nil {
		return nil, xerr
	}

	if len(resp) == 0 {
		return nil, fail.InconsistentError("no prices retrieved")
	}

	lastPrice := resp[len(resp)-1]
	logrus.Warnf("Last price detected %s", aws.StringValue(lastPrice.SpotPrice))

	instance, xerr := s.rpcRequestSpotInstance(
		ctx, lastPrice.SpotPrice, aws.String(zone), aws.String(netID), aws.Bool(publicIP), aws.String(template.ID),
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
	ctx context.Context,
	keypairName string,
	name string,
	imageID string,
	zone string,
	subnetID string,
	diskSize int,
	data string,
	publicIP bool,
	template abstract.HostTemplate,
) (*abstract.HostCore, fail.Error) {

	instance, xerr := s.rpcRunInstance(ctx,
		aws.String(name), aws.String(zone), aws.String(subnetID), aws.String(template.ID), aws.String(imageID), diskSize,
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
func (s stack) ClearHostStartupScript(ctx context.Context, hostParam stacks.HostParameter) fail.Error {
	return nil
}

// InspectHost loads information of a host from AWS
func (s stack) InspectHost(ctx context.Context, hostParam stacks.HostParameter) (ahf *abstract.HostFull, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	var hostLabel string
	var xerr fail.Error
	ahf, hostLabel, xerr = stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return nil, xerr
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostLabel).WithStopwatch().Entering().Exiting()

	var resp *ec2.Instance
	if ahf.Core.ID != "" {
		resp, xerr = s.rpcDescribeInstanceByID(ctx, aws.String(ahf.Core.ID))
		if xerr != nil {
			return nil, xerr
		}
	} else {
		resp, xerr = s.rpcDescribeInstanceByName(ctx, aws.String(ahf.Core.Name))
		if xerr != nil {
			return nil, xerr
		}
	}

	xerr = s.inspectInstance(ctx, ahf, hostLabel, resp)
	return ahf, xerr
}

func (s stack) inspectInstance(ctx context.Context, ahf *abstract.HostFull, hostLabel string, instance *ec2.Instance) (ferr fail.Error) {
	instanceName := ""
	instanceType := ""

	var xerr fail.Error
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
			Name: s.getTagOfSubnet(ctx, ni.SubnetId, tagNameLabel),
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

	sizing, xerr := s.fromMachineTypeToHostEffectiveSizing(ctx, instanceType)
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

func (s stack) fromMachineTypeToHostEffectiveSizing(ctx context.Context, machineType string) (abstract.HostEffectiveSizing, fail.Error) {
	nullSizing := abstract.HostEffectiveSizing{}
	resp, xerr := s.rpcDescribeInstanceTypeByID(ctx, aws.String(machineType))
	if xerr != nil {
		return nullSizing, xerr
	}

	hs := converters.HostTemplateToHostEffectiveSizing(*toAbstractHostTemplate(*resp))
	return *hs, nil
}

func (s stack) getTagOfSubnet(ctx context.Context, subnetID *string, str string) string {
	resp, xerr := s.rpcDescribeSubnetByID(ctx, subnetID)
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
func (s stack) InspectHostByName(ctx context.Context, name string) (_ *abstract.HostFull, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "('%s')", name).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&ferr)

	resp, xerr := s.rpcDescribeInstanceByName(ctx, aws.String(name))
	if xerr != nil {
		return nil, xerr
	}
	ahf := abstract.NewHostFull()
	return ahf, s.inspectInstance(ctx, ahf, "'"+name+"'", resp)
}

// GetHostState returns the current state of the host
func (s stack) GetHostState(ctx context.Context, hostParam stacks.HostParameter) (_ hoststate.Enum, ferr fail.Error) {
	if valid.IsNil(s) {
		return hoststate.Unknown, fail.InvalidInstanceError()
	}

	host, xerr := s.InspectHost(ctx, hostParam)
	if xerr != nil {
		return hoststate.Error, xerr
	}

	return host.CurrentState, nil
}

// ListHosts returns a list of hosts
func (s stack) ListHosts(ctx context.Context, details bool) (hosts abstract.HostList, ferr fail.Error) {
	nullList := abstract.HostList{}
	if valid.IsNil(s) {
		return nullList, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(details=%v)", details).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&ferr)

	resp, xerr := s.rpcDescribeInstances(ctx, nil)
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
				ahf, xerr = s.InspectHost(ctx, ahf)
				if xerr != nil {
					return nullList, xerr
				}
			}
			hosts = append(hosts, ahf)
		}
	}

	return hosts, nil
}

// DeleteHost deletes a Host
func (s stack) DeleteHost(ctx context.Context, hostParam stacks.HostParameter) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&ferr)

	vm, xerr := s.rpcDescribeInstanceByID(ctx, aws.String(ahf.GetID()))
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// a host not found is considered as a successful deletion, continue
			debug.IgnoreError(xerr)
			vm = nil
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
	if vm != nil {
		for _, attVol := range vm.BlockDeviceMappings {
			if attVol != nil && attVol.Ebs != nil && attVol.Ebs.VolumeId != nil {
				volume := aws.StringValue(attVol.Ebs.VolumeId)
				if volume != "" {
					attachedVolumes = append(attachedVolumes, volume)
				}
			}
		}

		keyPairName = aws.StringValue(vm.KeyName)
	}

	// Stop instance forcibly
	xerr = s.StopHost(ctx, ahf, false)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrAborted, *fail.ErrTimeout:
			cause := fail.ConvertError(xerr.Cause())
			switch cause.(type) {
			case *fail.ErrNotFound, *fail.ErrInvalidRequest:
				debug.IgnoreError(cause)
			default:
				return fail.Wrap(cause, "failed to stop Host '%s' with id '%s'", ahf.GetName(), ahf.GetID())
			}
		case *fail.ErrNotFound, *fail.ErrInvalidRequest:
			debug.IgnoreError(xerr)
		default:
			return fail.Wrap(xerr, "failed to stop Host '%s' with id '%s'", ahf.GetName(), ahf.GetID())
		}
	}

	// Terminate instance
	if vm != nil {
		xerr = s.rpcTerminateInstance(ctx, vm)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrAborted, *fail.ErrTimeout:
				xerr = fail.ConvertError(xerr.Cause())
				switch xerr.(type) {
				case *fail.ErrNotFound:
					debug.IgnoreError(xerr)
				default:
					return xerr
				}
			case *fail.ErrNotFound:
				debug.IgnoreError(xerr)
			default:
				return xerr
			}
		}
	}

	// Remove volumes if some remain, report errors (other than not found) as warnings
	for _, volume := range attachedVolumes {
		// TODO: parallelize ?
		xerr = stacks.RetryableRemoteCall(ctx,
			func() error {
				_, err := s.EC2Service.DeleteVolume(&ec2.DeleteVolumeInput{VolumeId: aws.String(volume)})
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
				logrus.Warnf("failed to delete volume %s (error %s)", volume, reflect.TypeOf(xerr).String())
			}
		}
	}

	// Remove keypair
	if keyPairName != "" {
		xerr = s.rpcDeleteKeyPair(ctx, aws.String(keyPairName))
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
func (s stack) StopHost(ctx context.Context, host stacks.HostParameter, gracefully bool) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(ctx, host)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&ferr)

	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	if xerr = s.rpcStopInstances(ctx, []*string{aws.String(ahf.Core.ID)}, aws.Bool(gracefully)); xerr != nil {
		return xerr
	}

	retryErr := retry.WhileUnsuccessful(
		func() error {
			hostTmp, err := s.InspectHost(ctx, ahf.Core.ID)
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
		timings.NormalDelay(),
		timings.HostCleanupTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry:
			return fail.Wrap(fail.Cause(retryErr), "stopping retries")
		case *retry.ErrTimeout:
			return fail.Wrap(
				fail.Cause(retryErr), "timeout waiting to get host '%s' information after %v", hostRef,
				timings.HostCleanupTimeout(),
			)
		default:
			return retryErr
		}
	}

	return nil
}

// StartHost starts a stopped host
func (s stack) StartHost(ctx context.Context, hostParam stacks.HostParameter) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&ferr)

	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	xerr = s.rpcStartInstances(ctx, []*string{aws.String(ahf.Core.ID)})
	if xerr != nil {
		return xerr
	}

	retryErr := retry.WhileUnsuccessful(
		func() error {
			hostTmp, innerErr := s.InspectHost(ctx, ahf.Core.ID)
			if innerErr != nil {
				return innerErr
			}

			if hostTmp.CurrentState != hoststate.Started {
				return fail.NewError("not in started state (current state: %s)", hostTmp.CurrentState.String())
			}
			return nil
		},
		timings.NormalDelay(),
		timings.HostCleanupTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry:
			return fail.Wrap(fail.Cause(retryErr), "stopping retries")
		case *retry.ErrTimeout:
			return fail.Wrap(
				fail.Cause(retryErr), "timeout waiting to get information of host '%s' after %v", hostRef,
				timings.HostCleanupTimeout(),
			)
		default:
			return retryErr
		}
	}

	return nil
}

// RebootHost stops then starts a host
func (s stack) RebootHost(ctx context.Context, hostParam stacks.HostParameter) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.aws") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()
	defer fail.OnExitTraceError(&ferr)

	if xerr = s.rpcRebootInstances(ctx, []*string{aws.String(ahf.Core.ID)}); xerr != nil {
		return xerr
	}

	retryErr := retry.WhileUnsuccessful(
		func() error {
			hostTmp, innerErr := s.InspectHost(ctx, ahf)
			if innerErr != nil {
				return innerErr
			}

			if hostTmp.CurrentState != hoststate.Started {
				return fail.NewError("not in started state (current state: %s)", hostTmp.CurrentState.String())
			}
			return nil
		},
		timings.NormalDelay(),
		2*timings.HostCleanupTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry:
			return fail.Wrap(fail.Cause(retryErr), "stopping retries")
		case *retry.ErrTimeout:
			return fail.Wrap(
				fail.Cause(retryErr), "timeout waiting to get host '%s' information after %v", hostRef,
				timings.HostCleanupTimeout(),
			)
		default:
			return retryErr
		}
	}

	return nil
}

// ResizeHost changes the sizing of an existing host
func (s stack) ResizeHost(ctx context.Context, hostParam stacks.HostParameter, request abstract.HostSizingRequirements) (*abstract.HostFull, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	return nil, fail.NotImplementedError("ResizeHost() not implemented yet") // FIXME: Technical debt
}

// BindSecurityGroupToHost ...
// Returns:
// - *fail.ErrNotFound if the Host is not found
func (s stack) BindSecurityGroupToHost(ctx context.Context, sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}
	if !ahf.IsConsistent() {
		if ahf, xerr = s.InspectHost(ctx, ahf); xerr != nil {
			return xerr
		}
	}
	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam) // nolint
	if xerr != nil {
		return xerr
	}
	if !asg.IsConsistent() {
		if asg, xerr = s.InspectSecurityGroup(ctx, asg); xerr != nil {
			return xerr
		}
	}

	resp, xerr := s.rpcDescribeInstanceByID(ctx, aws.String(ahf.GetID()))
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
	if xerr = s.rpcModifyInstanceSecurityGroups(ctx, aws.String(ahf.GetID()), sgs); xerr != nil {
		return xerr
	}

	return nil
}

// UnbindSecurityGroupFromHost ...
// Returns:
// - nil means success
// - *fail.ErrNotFound if the Host or the Security Group ID cannot be identified
func (s stack) UnbindSecurityGroupFromHost(ctx context.Context, sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}
	if !ahf.IsConsistent() {
		ahf, xerr = s.InspectHost(ctx, ahf)
		if xerr != nil {
			return xerr
		}
	}
	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam) // nolint
	if xerr != nil {
		return xerr
	}

	if !asg.IsComplete() {
		asg, xerr = s.InspectSecurityGroup(ctx, asg)
		if xerr != nil {
			return xerr
		}
	}

	// query the instance to get its current Security Groups
	resp, xerr := s.rpcDescribeInstanceByID(ctx, aws.String(ahf.GetID()))
	if xerr != nil {
		return xerr
	}

	sgs := make([]*string, 0, len(resp.SecurityGroups)+1)

	// If there is one last Security Group bound to Host, restore bond to default SecurityGroup before removing
	if len(resp.SecurityGroups) == 1 && aws.StringValue(resp.SecurityGroups[0].GroupId) == asg.ID {
		defaultSG := abstract.NewSecurityGroup()
		var err fail.Error
		defaultSG.Name, err = s.GetDefaultSecurityGroupName(ctx)
		if err != nil {
			return err
		}
		defaultSG.Network = asg.Network
		defaultSG, xerr := s.InspectSecurityGroup(ctx, defaultSG)
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

	return s.rpcModifyInstanceSecurityGroups(ctx, aws.String(ahf.GetID()), sgs)
}
