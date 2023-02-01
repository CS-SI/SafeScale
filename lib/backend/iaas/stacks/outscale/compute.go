/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

package outscale

import (
	"bytes"
	"context"
	"encoding/base64"
	"expvar"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"
	"github.com/zserge/metric"

	"github.com/outscale/osc-sdk-go/osc"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
)

const maxMemorySize int = 1039

func normalizeImageName(name string) string {
	if len(name) == 0 {
		return name
	}

	n := strings.Replace(name, "-", " ", 1)
	n = strings.Replace(n, "-", " (", 1)
	n = strings.Replace(n, ".", ",", 1)
	n = strings.ReplaceAll(n, ".", "")
	n = strings.Replace(n, ",", ".", 1)
	n = strings.ReplaceAll(n, "-0", ")")
	tok := strings.Split(n, " (")

	if len(tok) == 0 {
		return name
	}

	return tok[0]
}

// ListImages lists available OS images
func (s stack) ListImages(ctx context.Context, _ bool) (_ []*abstract.Image, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	resp, xerr := s.rpcReadImages(ctx, nil)
	if xerr != nil {
		return nil, xerr
	}

	var images []*abstract.Image
	for _, omi := range resp {
		images = append(
			images, &abstract.Image{
				Description: omi.Description,
				ID:          omi.ImageId,
				Name:        normalizeImageName(omi.ImageName),
				URL:         omi.FileLocation,
				StorageType: omi.RootDeviceType,
			},
		)
	}
	return images, nil
}

func intRange(start, stop, step int) []int {
	var r []int
	for i := start; i <= stop; i += step {
		r = append(r, i)
	}
	return r
}

func gpuTemplateName(version, cpu, ram, perf, gpu int, gpuType string) (name string) {
	if version == 0 {
		name = fmt.Sprintf("tina.c%dr%dp%d", cpu, ram, perf)
		return
	}
	name = fmt.Sprintf("tinav%d.c%dr%dp%d.g%dt%s", version, cpu, ram, perf, gpu, gpuType)
	return
}

func (s stack) cpuFreq(perf int) float32 {
	freq := float32(2.0)
	if f, ok := s.CPUPerformanceMap[perf]; ok {
		freq = f
	}
	return freq
}

func parseSizing(s string) (cpus, ram, perf int, ferr fail.Error) {
	tokens := strings.FieldsFunc(
		s, func(r rune) bool {
			return r == 'c' || r == 'r' || r == 'p' || r == 'g'
		},
	)

	if len(tokens) < 2 {
		return 0, 0, 0, fail.InconsistentError("error parsing sizing string")
	}

	var err error
	cpus, err = strconv.Atoi(tokens[0])
	if err != nil {
		return 0, 0, 0, fail.ConvertError(err)
	}
	ram, err = strconv.Atoi(tokens[1])
	if err != nil {
		return 0, 0, 0, fail.ConvertError(err)
	}
	perf = 2
	if len(tokens) < 3 {
		return
	}
	perf, err = strconv.Atoi(tokens[2])
	if err != nil {
		return 0, 0, 0, fail.ConvertError(err)
	}

	return
}

func parseGPU(s string) (gpus int, gpuType string, ferr fail.Error) {
	tokens := strings.FieldsFunc(
		s, func(r rune) bool {
			return r == 'g' || r == 't'
		},
	)
	if len(tokens) < 2 {
		return 0, "", fail.InvalidParameterError("id", "malformed id")
	}
	var err error
	gpus, err = strconv.Atoi(tokens[0])
	if err != nil {
		return 0, "", fail.ConvertError(err)
	}
	gpuType = tokens[1]
	return
}

func (s stack) parseTemplateID(id string) (*abstract.HostTemplate, fail.Error) {
	tokens := strings.Split(id, ".")
	if len(tokens) < 2 || !strings.HasPrefix(id, "tina") {
		return nil, fail.InvalidParameterError("id", "invalid template id")
	}

	cpus, ram, perf, err := parseSizing(tokens[1])
	if err != nil {
		return nil, fail.InvalidParameterError("id", "invalid template id")
	}
	gpus := 0
	gpuType := ""
	if len(tokens) > 2 {
		gpus, gpuType, err = parseGPU(tokens[2])
		if err != nil {
			return nil, fail.InvalidParameterError("id", "invalid template id")
		}
	}
	return &abstract.HostTemplate{
		Cores:     cpus,
		CPUFreq:   s.cpuFreq(perf),
		GPUNumber: gpus,
		GPUType:   gpuType,
		RAMSize:   float32(ram),
		DiskSize:  0,
		Name:      id,
		ID:        id,
	}, nil
}

// ListTemplates lists available host templates
// Host templates are sorted using Dominant Resource Fairness Algorithm
func (s stack) ListTemplates(ctx context.Context, _ bool) (_ []*abstract.HostTemplate, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	templates := make([]*abstract.HostTemplate, len(s.templates))
	_ = copy(templates, s.templates)
	return templates, nil
}

func (s *stack) buildTemplateList() {
	// without GPU
	cpus := intRange(1, 78, 1)
	ramPerCore := intRange(1, 16, 1)
	perfLevels := []int{1, 2, 3}

	for _, cpu := range cpus {
		for _, ramCore := range ramPerCore {
			for _, perf := range perfLevels {
				ram := cpu * ramCore
				// Outscale maximum memory size
				if ram > maxMemorySize {
					break
				}

				name := gpuTemplateName(0, cpu, ram, perf, 0, "")
				s.templates = append(s.templates, &abstract.HostTemplate{
					DiskSize:  0,
					Name:      name,
					Cores:     cpu,
					RAMSize:   float32(ram),
					ID:        name,
					CPUFreq:   s.cpuFreq(perf),
					GPUNumber: 0,
				})
			}
		}
	}

	// instances with gpu https://wiki.outscale.net/pages/viewpage.action?pageId=49023126
	// with nvidia-k2 GPU
	gpus := intRange(1, 8, 2)
	for _, gpu := range gpus {
		for _, cpu := range cpus {
			for _, ramCore := range ramPerCore {
				for _, perf := range perfLevels {
					ram := cpu * ramCore
					// Outscale maximum memory size
					if ram > maxMemorySize {
						break
					}

					name := gpuTemplateName(3, cpu, ram, perf, gpu, "nvidia-k2")
					s.templates = append(s.templates, &abstract.HostTemplate{
						DiskSize:  0,
						Name:      name,
						Cores:     cpu,
						RAMSize:   float32(ram),
						CPUFreq:   s.cpuFreq(perf),
						ID:        name,
						GPUNumber: gpu,
						GPUType:   "nvidia-k2",
					})
				}
			}
		}
	}

	// with nvidia-p6 gpu
	for _, gpu := range gpus {
		for _, cpu := range cpus {
			for _, ramCore := range ramPerCore {
				for _, perf := range perfLevels {
					ram := cpu * ramCore
					// Outscale maximum memory size
					if ram > maxMemorySize {
						break
					}

					name := gpuTemplateName(5, cpu, ram, perf, gpu, "nvidia-p6")
					s.templates = append(s.templates, &abstract.HostTemplate{
						DiskSize:  0,
						Name:      name,
						Cores:     cpu,
						RAMSize:   float32(ram),
						CPUFreq:   s.cpuFreq(perf),
						ID:        name,
						GPUNumber: gpu,
						GPUType:   "nvidia-p6",
					})
				}
			}
		}
	}

	// with nvidia-p100 gpu
	for _, gpu := range gpus {
		for _, cpu := range cpus {
			for _, ramCore := range ramPerCore {
				for _, perf := range perfLevels {
					ram := cpu * ramCore
					// Outscale maximum memory size
					if ram > maxMemorySize {
						break
					}

					name := gpuTemplateName(5, cpu, ram, perf, gpu, "nvidia-p100")
					s.templates = append(s.templates, &abstract.HostTemplate{
						DiskSize:  0,
						Name:      name,
						Cores:     cpu,
						RAMSize:   float32(ram),
						CPUFreq:   s.cpuFreq(perf),
						ID:        name,
						GPUNumber: gpu,
						GPUType:   "nvidia-p100",
					})
				}
			}
		}
	}
}

// InspectImage returns the Image referenced by id
func (s stack) InspectImage(ctx context.Context, id string) (_ *abstract.Image, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			ferr = fail.Wrap(ferr, fmt.Sprintf("failed to get image '%s'", id))
		}
	}()

	resp, xerr := s.rpcReadImageByID(ctx, id)
	if xerr != nil {
		return nil, xerr
	}

	return toAbstractImage(resp), nil
}

func toAbstractImage(in osc.Image) *abstract.Image {
	return &abstract.Image{
		Description: in.Description,
		ID:          in.ImageId,
		Name:        in.ImageName,
		StorageType: in.RootDeviceType,
		URL:         in.FileLocation,
	}
}

// InspectTemplate returns the Template referenced by id
func (s stack) InspectTemplate(ctx context.Context, id string) (_ *abstract.HostTemplate, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	return s.parseTemplateID(id)
}

func (s stack) getOrCreatePassword(request abstract.HostRequest) (string, fail.Error) {
	if request.Password == "" {
		password, err := utils.GeneratePassword(16)
		if err != nil {
			return "", fail.Wrap(err, "failed to generate password")
		}
		return password, nil
	}
	return request.Password, nil
}

func (s stack) prepareUserData(ctx context.Context, request abstract.HostRequest, ud *userdata.Content) fail.Error {
	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	cidr := func() string {
		if len(request.Subnets) == 0 {
			return ""
		}
		return request.Subnets[0].CIDR
	}()
	if xerr := ud.Prepare(*s.configurationOptions, request, cidr, "", timings); xerr != nil {
		msg := "failed to prepare user data content"
		logrus.WithContext(ctx).Debugf(strprocess.Capitalize(msg + ": " + xerr.Error()))
		return fail.Wrap(xerr, msg)
	}
	return nil
}

func (s stack) createNIC(ctx context.Context, request *abstract.HostRequest, subnet *abstract.Subnet) (osc.Nic, fail.Error) {
	name := fmt.Sprintf("nic_%s_subnet_%s", request.ResourceName, subnet.Name)
	description := fmt.Sprintf("nic of Host %s on Subnet %s", request.ResourceName, subnet.Name)
	resp, xerr := s.rpcCreateNic(ctx, name, subnet.ID, description, nil)
	if xerr != nil {
		return osc.Nic{}, xerr
	}
	// primary := deviceNumber == 0
	return resp, nil
}

func (s stack) createNICs(ctx context.Context, request *abstract.HostRequest) (nics []osc.Nic, ferr fail.Error) {
	nics = []osc.Nic{}

	// first network is the default network
	var xerr fail.Error
	nics, xerr = s.tryCreateNICS(ctx, request, nics)
	if xerr != nil { // if error delete created NICS
		for _, v := range nics {
			xerr := s.rpcDeleteNic(ctx, v.NicId)
			if xerr != nil {
				logrus.WithContext(ctx).Errorf("impossible to delete NIC '%s': %v", v.NicId, xerr)
			}
		}
	}
	return nics, xerr
}

func (s stack) tryCreateNICS(ctx context.Context, request *abstract.HostRequest, nics []osc.Nic) ([]osc.Nic, fail.Error) {
	for _, n := range request.Subnets[1:] {
		nic, xerr := s.createNIC(ctx, request, n)
		if xerr != nil {
			return nics, xerr
		}
		nics = append(nics, nic)
	}
	return nics, nil
}

func (s stack) deleteNICs(ctx context.Context, nics []osc.Nic) fail.Error {
	for _, nic := range nics {
		// TODO: parallelize ?
		if xerr := s.rpcDeleteNic(ctx, nic.NicId); xerr != nil {
			return xerr
		}
	}
	return nil
}

func hostState(state string) hoststate.Enum {
	if state == "pending" {
		return hoststate.Starting
	}
	if state == "running" {
		return hoststate.Started
	}
	if state == "stopping" || state == "shutting-down" {
		return hoststate.Stopping
	}
	if state == "stopped" {
		return hoststate.Stopped
	}
	if state == "terminated" {
		return hoststate.Terminated
	}
	if state == "quarantine" {
		return hoststate.Error
	}
	return hoststate.Unknown
}

func (s stack) hostState(ctx context.Context, id string) (hoststate.Enum, fail.Error) {
	vm, xerr := s.rpcReadVMByID(ctx, id)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return hoststate.Terminated, nil
		default:
			return hoststate.Error, xerr
		}
	}
	return hostState(vm.State), nil
}

// WaitHostReady waits a host achieve ready state
// hostParam can be an ID of host, or an instance of *abstract.HostCore; any other type will return a utils.ErrInvalidParameter
func (s stack) WaitHostReady(ctx context.Context, hostParam stacks.HostParameter, timeout time.Duration) (*abstract.HostCore, fail.Error) {
	if valid.IsNil(s) {
		return abstract.NewHostCore(), fail.InvalidInstanceError()
	}

	return s.WaitHostState(ctx, hostParam, hoststate.Started, timeout)
}

// WaitHostState wait for host to be in the specified state
// On exit, xerr may be of type:
// - *retry.ErrTimeout: when the timeout is reached
// - *retry.ErrStopRetry: when a breaking error arises; fail.Cause(xerr) contains the real error encountered
// - fail.Error: any other errors
func (s stack) WaitHostState(ctx context.Context, hostParam stacks.HostParameter, state hoststate.Enum, timeout time.Duration) (_ *abstract.HostCore, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return nil, xerr
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, xerr
	}

	xerr = retry.WhileUnsuccessfulWithHardTimeout(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			st, innerXErr := s.hostState(ctx, ahf.Core.ID)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					// if waited state is Terminated, a missing host means a terminated host, so consider this as a success
					if state != hoststate.Terminated {
						return innerXErr
					}
					debug.IgnoreError2(ctx, innerXErr)
					st = hoststate.Terminated
				default:
					return innerXErr
				}
			}

			switch st {
			case hoststate.Error:
				return retry.StopRetryError(fail.NewError("host in 'error' state"))
			case state:
				ahf.CurrentState, ahf.Core.LastState = st, st
				return nil
			default:
				return fail.NewError("wrong state: %s", st)
			}
		},
		timings.NormalDelay(),
		timeout,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrTimeout:
			return nil, fail.Wrap(fail.Cause(xerr), "timeout")
		case *retry.ErrStopRetry:
			return nil, fail.Wrap(fail.Cause(xerr), "stopping retries")
		default:
			return nil, xerr
		}
	}
	return ahf.Core, nil
}

func outscaleTemplateID(id string) (string, fail.Error) {
	tokens := strings.Split(id, ".")
	if len(tokens) < 2 {
		return "", fail.InvalidParameterError("id", "malformed template id")
	}
	if len(tokens) == 2 {
		return id, nil
	}
	return fmt.Sprintf("%s.%s", tokens[0], tokens[1]), nil
}

func (s stack) addNICs(ctx context.Context, request *abstract.HostRequest, vmID string) ([]osc.Nic, fail.Error) {
	if len(request.Subnets) > 1 {
		nics, xerr := s.createNICs(ctx, request)
		if xerr != nil {
			return nil, xerr
		}
		for i, nic := range nics {
			xerr = s.rpcLinkNic(ctx, vmID, nic.NicId, int32(i+1))
			if xerr != nil {
				logrus.WithContext(ctx).Errorf("failed to attach NIC %s to Host %s: %v", nic.NicId, vmID, xerr)
				return nil, xerr
			}
		}
		return nics, nil
	}
	return []osc.Nic{}, nil
}

func (s stack) addGPUs(ctx context.Context, request *abstract.HostRequest, tpl abstract.HostTemplate, vmID string) (ferr fail.Error) {
	if tpl.GPUNumber <= 0 {
		return nil
	}

	var (
		flexibleGpus []osc.FlexibleGpu
		createErr    fail.Error
		resp         osc.FlexibleGpu
	)
	var xerr fail.Error
	for gpu := 0; gpu < tpl.GPUNumber; gpu++ {
		resp, xerr = s.rpcCreateFlexibleGpu(ctx, tpl.GPUType)
		if xerr != nil {
			createErr = xerr
			break
		}
		flexibleGpus = append(flexibleGpus, resp)

		xerr = s.rpcLinkFlexibleGpu(ctx, vmID, resp.FlexibleGpuId)
		if xerr != nil {
			break
		}
	}
	if xerr != nil {
		for _, gpu := range flexibleGpus {
			if rerr := s.rpcDeleteFlexibleGpu(ctx, gpu.FlexibleGpuId); rerr != nil {
				_ = xerr.AddConsequence(fail.Wrap(rerr, "cleaning up on failure, failed to delete Flexible GPU"))
			}
		}
		return xerr
	}
	return createErr
}

func (s stack) addPublicIP(ctx context.Context, nic osc.Nic) (_ osc.PublicIp, ferr fail.Error) {
	// Allocate public IP
	resp, xerr := s.rpcCreatePublicIP(ctx)
	if xerr != nil {
		return osc.PublicIp{}, xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			if derr := s.rpcDeletePublicIPByID(context.Background(), resp.PublicIpId); derr != nil {
				_ = ferr.AddConsequence(
					fail.Wrap(
						derr, "cleaning up on failure, failed to delete public IP with ID %s", resp.PublicIpId,
					),
				)
			}
		}
	}()

	// Attach public ip
	if xerr = s.rpcLinkPublicIP(ctx, resp.PublicIpId, nic.NicId); xerr != nil {
		return osc.PublicIp{}, xerr
	}

	return resp, nil
}

func (s stack) setHostProperties(
	ctx context.Context, ahf *abstract.HostFull, subnets []*abstract.Subnet, vm osc.Vm, nics []osc.Nic,
) fail.Error {
	vmType, xerr := s.InspectTemplate(ctx, vm.VmType)
	if xerr != nil {
		return xerr
	}

	state := hostState(vm.State)
	ahf.CurrentState, ahf.Core.LastState = state, state

	// Updates Host Property propsv1.HostDescription
	ahf.Description.Created = time.Now()
	ahf.Description.Updated = ahf.Description.Created

	// Updates Host Property propsv1.HostSizing
	ahf.Sizing.Cores = vmType.Cores
	ahf.Sizing.CPUFreq = vmType.CPUFreq
	ahf.Sizing.DiskSize = vmType.DiskSize
	ahf.Sizing.GPUNumber = vmType.GPUNumber
	ahf.Sizing.GPUType = vmType.GPUType
	ahf.Sizing.RAMSize = vmType.RAMSize

	// Updates Host Property propsv1.HostNetworking
	// subnets contains network names, but IPxAddresses has to be
	// indexed on network ID. Tries to convert if possible, if we already have correspondence
	// between network ID and network Name in Host definition
	subnetsByID := map[string]string{}
	subnetsByName := map[string]string{}
	ipv4Addresses := map[string]string{}
	ipv6Addresses := map[string]string{}
	for i, net := range subnets {
		nic := nics[i]
		subnetsByID[net.ID] = net.Name
		subnetsByName[net.Name] = net.ID
		ipv4Addresses[net.ID] = func() string {
			for _, addr := range nic.PrivateIps {
				if addr.IsPrimary {
					return addr.PrivateIp
				}
			}
			return ""
		}()
	}
	ahf.Networking.SubnetsByID = subnetsByID
	ahf.Networking.SubnetsByName = subnetsByName
	// IPvxAddresses are here indexed by names... At least we have them...
	ahf.Networking.IPv4Addresses = ipv4Addresses
	ahf.Networking.IPv6Addresses = ipv6Addresses
	ahf.Networking.PublicIPv4 = vm.PublicIp

	return nil
}

func (s stack) initHostProperties(
	ctx context.Context, request *abstract.HostRequest, host *abstract.HostFull, udc userdata.Content,
) fail.Error {
	defaultSubnet := func() *abstract.Subnet {
		if len(request.Subnets) == 0 {
			return nil
		}
		return request.Subnets[0]
	}()

	isGateway := request.IsGateway // && defaultSubnet != nil && defaultSubnet.Name != abstract.SingleHostNetworkName
	template, err := s.InspectTemplate(ctx, request.TemplateID)
	if err != nil {
		return err
	}

	host.Core.PrivateKey = udc.FirstPrivateKey
	host.Core.Password = request.Password

	host.Networking.DefaultSubnetID = func() string {
		if defaultSubnet == nil {
			return ""
		}
		return defaultSubnet.ID
	}()
	// host.Networking.DefaultGatewayID = defaultGatewayID
	// host.Networking.DefaultGatewayPrivateIP = request.DefaultRouteIP
	host.Networking.IsGateway = isGateway

	// Adds Host property SizingV1
	host.Sizing.Cores = template.Cores
	host.Sizing.CPUFreq = template.CPUFreq
	host.Sizing.RAMSize = template.RAMSize
	host.Sizing.DiskSize = template.DiskSize
	host.Sizing.GPUNumber = template.GPUNumber
	host.Sizing.GPUType = template.GPUType
	return nil
}

func (s stack) addPublicIPs(ctx context.Context, primaryNIC osc.Nic, otherNICs []osc.Nic) (osc.PublicIp, fail.Error) {
	ip, xerr := s.addPublicIP(ctx, primaryNIC)
	if xerr != nil {
		return osc.PublicIp{}, xerr
	}

	for _, nic := range otherNICs {
		if _, xerr = s.addPublicIP(ctx, nic); xerr != nil {
			return osc.PublicIp{}, xerr
		}
	}
	return ip, nil
}

// CreateHost creates a host that fulfills the request
func (s stack) CreateHost(ctx context.Context, request abstract.HostRequest, extra interface{}) (ahf *abstract.HostFull, udc *userdata.Content, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(s) {
		return nil, nil, fail.InvalidInstanceError()
	}
	if len(request.Subnets) == 0 && !request.PublicIP {
		return nil, nil, abstract.ResourceInvalidRequestError(
			"host creation", "cannot create a host without public IP or without attached subnet",
		)
	}

	// Get or create password
	password, xerr := s.getOrCreatePassword(request)
	if xerr != nil {
		return nil, nil, xerr
	}
	request.Password = password

	// gather default subnet ID
	subnetID, xerr := s.getDefaultSubnetID(request)
	if xerr != nil {
		return nil, nil, xerr
	}

	// Build KeyPair and password if not provided
	if xerr = stacks.ProvideCredentialsIfNeeded(&request); xerr != nil {
		return nil, nil, fail.Wrap(xerr, "failed to provide credentials for Host")
	}

	// Configure userdata content
	udc = userdata.NewContent()
	if xerr = s.prepareUserData(ctx, request, udc); xerr != nil {
		return nil, nil, xerr
	}

	// Using udc.FirstPublicKey in creation keypair
	creationKeyPair := &abstract.KeyPair{
		Name:      request.ResourceName + "_install",
		PublicKey: udc.FirstPublicKey,
	}
	if xerr = s.ImportKeyPair(ctx, creationKeyPair); xerr != nil {
		return nil, nil, xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if derr := s.DeleteKeyPair(context.Background(), creationKeyPair.Name); derr != nil {
			logrus.WithContext(ctx).Errorf("Cleaning up on failure, failed to delete creation keypair: %v", derr)
			if ferr != nil {
				_ = ferr.AddConsequence(derr)
			}
		}
	}()

	ahf = abstract.NewHostFull()
	if xerr = s.initHostProperties(ctx, &request, ahf, *udc); xerr != nil {
		return nil, nil, xerr
	}

	// -- prepare userdata phase1 execution --
	userDataPhase1, xerr := udc.Generate(userdata.PHASE1_INIT)
	if xerr != nil {
		return nil, nil, xerr
	}

	vmType, xerr := outscaleTemplateID(request.TemplateID)
	if xerr != nil {
		return nil, nil, xerr
	}

	buf := bytes.NewBuffer(userDataPhase1)

	// -- create host --
	vmsRequest := osc.CreateVmsRequest{
		ImageId:  request.ImageID,
		UserData: base64.StdEncoding.EncodeToString(buf.Bytes()),
		VmType:   vmType,
		SubnetId: subnetID,
		Placement: osc.Placement{
			SubregionName: s.Options.Compute.Subregion,
			Tenancy:       s.Options.Compute.DefaultTenancy,
		},
		KeypairName: creationKeyPair.Name,
	}

	template, xerr := s.InspectTemplate(ctx, request.TemplateID)
	if xerr != nil {
		return nil, nil, xerr
	}

	rim, xerr := s.InspectImage(ctx, request.ImageID)
	if xerr != nil {
		return nil, nil, xerr
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

	vmsRequest.BlockDeviceMappings = []osc.BlockDeviceMappingVmCreation{
		{
			Bsu: osc.BsuToCreate{
				DeleteOnVmDeletion: true,
				SnapshotId:         "",
				VolumeSize:         int32(diskSize),
				VolumeType:         s.fromAbstractVolumeSpeed(s.Options.Compute.DefaultVolumeSpeed),
			},
			NoDevice:   "true",
			DeviceName: "/dev/sda1",
		},
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, nil, xerr
	}

	var vm osc.Vm

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			logrus.WithContext(ctx).Debugf("Cleaning up on failure, deleting Host '%s'", request.HostName)
			if vm.VmId != "" {
				if derr := s.DeleteHost(context.Background(), vm.VmId); derr != nil {
					msg := fmt.Sprintf("cleaning up on failure, failed to delete Host '%s'", request.HostName)
					logrus.WithContext(ctx).Errorf(strprocess.Capitalize(msg))
					return
				}
			}
			logrus.WithContext(ctx).Debugf("Cleaning up on failure, deleted Host '%s' successfully.", request.HostName)
		}
	}()

	xerr = retry.WhileUnsuccessful(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			resp, innerXErr := s.rpcCreateVMs(ctx, vmsRequest)
			if innerXErr != nil {
				casted := normalizeError(innerXErr)
				switch casted.(type) {
				case *fail.ErrNotFound, *fail.ErrDuplicate, *fail.ErrInvalidRequest, *fail.ErrNotAuthenticated, *fail.ErrForbidden, *fail.ErrOverflow, *fail.ErrSyntax, *fail.ErrInconsistent, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent, *fail.ErrInvalidParameter, *fail.ErrRuntimePanic: // Do not retry if it's going to fail anyway
					return retry.StopRetryError(casted)
				default:
					return casted
				}
			}

			if len(resp) == 0 {
				return retry.StopRetryError(fail.InconsistentError("after creation submission, virtual machine list is empty"))
			}
			vm = resp[0]

			// Delete instance if created to be in good shape to retry in case of error
			defer func() {
				if innerXErr != nil {
					logrus.WithContext(ctx).Debugf("Cleaning up on failure, deleting Host '%s'", request.HostName)
					if derr := s.DeleteHost(context.Background(), vm.VmId); derr != nil {
						msg := fmt.Sprintf("cleaning up on failure, failed to delete Host '%s'", request.HostName)
						logrus.WithContext(ctx).Errorf(strprocess.Capitalize(msg))
						return
					}
					logrus.WithContext(ctx).Debugf("Cleaning up on failure, deleted Host '%s' successfully.", request.HostName)
				}
			}()

			_, innerXErr = s.WaitHostState(ctx, vm.VmId, hoststate.Started, timings.HostOperationTimeout())
			return innerXErr
		},
		timings.NormalDelay(),
		timings.HostLongOperationTimeout(),
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry, *fail.ErrNotFound, *fail.ErrDuplicate, *fail.ErrInvalidRequest, *fail.ErrNotAuthenticated, *fail.ErrForbidden, *fail.ErrOverflow, *fail.ErrSyntax, *fail.ErrInconsistent, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent, *fail.ErrInvalidParameter, *fail.ErrRuntimePanic: // Do not retry if it's going to fail anyway
			return nil, nil, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout:
			return nil, nil, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return nil, nil, xerr
		}
	}

	// -- Retrieve default Nic use to create public ip --
	nics, xerr := s.rpcReadNics(ctx, "", vm.VmId)
	if xerr != nil {
		return nil, nil, xerr
	}
	if len(nics) == 0 {
		return nil, nil, fail.InconsistentError("No network interface associated to vm")
	}
	defaultNic := nics[0]

	nics, xerr = s.addNICs(ctx, &request, vm.VmId)
	if xerr != nil {
		return nil, nil, xerr
	}
	if request.PublicIP {
		ip, xerr := s.addPublicIPs(ctx, defaultNic, nics)
		if xerr != nil {
			return nil, nil, xerr
		}
		udc.PublicIP = ip.PublicIp
		vm.PublicIp = udc.PublicIP
	}

	// -- add GPU if asked for --
	if xerr = s.addGPUs(ctx, &request, *template, vm.VmId); xerr != nil {
		return nil, nil, xerr
	}

	into := map[string]string{
		"name":             request.ResourceName,
		"ManagedBy":        "safescale",
		"DeclaredInBucket": s.configurationOptions.MetadataBucket,
		"CreationDate":     time.Now().Format(time.RFC3339),
		"Template":         vm.VmType,
		"Image":            vm.ImageId,
	}
	if extra != nil {
		theSame, ok := extra.(map[string]string)
		if !ok {
			return nil, nil, fail.InvalidParameterError("extra", "must be a map[string]string")
		}
		for k, v := range theSame {
			k, v := k, v
			into[k] = v
		}
	}

	_, xerr = s.rpcCreateTags(ctx,
		vm.VmId, into,
	)
	if xerr != nil {
		return nil, nil, xerr
	}

	_, xerr = s.WaitHostState(ctx, vm.VmId, hoststate.Started, timings.HostOperationTimeout())
	if xerr != nil {
		return nil, nil, xerr
	}

	ahf = abstract.NewHostFull()
	ahf.Core.ID = vm.VmId
	ahf.Core.Name = request.ResourceName
	ahf.Core.Password = request.Password
	ahf.Core.PrivateKey = udc.FirstPrivateKey
	ahf.CurrentState, ahf.Core.LastState = hoststate.Started, hoststate.Started

	ahf.Core.Tags["Template"] = vm.VmType
	ahf.Core.Tags["Image"] = vm.ImageId

	// recover metadata
	for _, rt := range vm.Tags {
		ahf.Core.Tags[rt.Key] = rt.Value
	}

	nics = append(nics, defaultNic)
	xerr = s.setHostProperties(ctx, ahf, request.Subnets, vm, nics)
	return ahf, udc, xerr
}

func (s stack) getDefaultSubnetID(request abstract.HostRequest) (string, fail.Error) {
	if len(request.Subnets) == 0 {
		return "", nil
	}
	if request.Subnets[0] != nil {
		return request.Subnets[0].ID, nil
	}

	return "", fail.InconsistentError("Invalid request: %v", request)
}

func (s stack) deleteHost(ctx context.Context, id string) fail.Error {
	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	if xerr := s.rpcDeleteVms(ctx, []string{id}); xerr != nil {
		return xerr
	}
	_, xerr = s.WaitHostState(ctx, id, hoststate.Terminated, timings.HostCreationTimeout())
	return xerr
}

// ClearHostStartupScript clears the userdata startup script for Host instance (metadata service)
func (s stack) ClearHostStartupScript(ctx context.Context, hostParam stacks.HostParameter) fail.Error {
	return nil
}

func (s stack) ChangeSecurityGroupSecurity(ctx context.Context, b bool, b2 bool, net string, s2 string) fail.Error {
	return nil
}

// DeleteHost deletes the host identified by id
func (s stack) DeleteHost(ctx context.Context, hostParam stacks.HostParameter) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	publicIPs, xerr := s.rpcReadPublicIPsOfVM(ctx, ahf.Core.ID)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to read public IPs of Host with ID %s", ahf.Core.ID)
	}

	// list attached volumes
	volumes, xerr := s.ListVolumeAttachments(ctx, ahf.Core.ID)
	if xerr != nil {
		volumes = []*abstract.VolumeAttachment{}
	}

	// delete host
	if xerr = s.deleteHost(ctx, ahf.Core.ID); xerr != nil {
		return xerr
	}

	// delete public IPs
	if len(publicIPs) == 0 {
		return nil
	}
	var lastErr fail.Error
	for _, ip := range publicIPs {
		if xerr = s.rpcDeletePublicIPByID(ctx, ip.PublicIpId); xerr != nil { // continue to delete even if error
			lastErr = xerr
			logrus.WithContext(ctx).Errorf("failed to delete public IP %s of Host %s: %v", ip.PublicIpId, ahf.Core.ID, xerr)
		}
	}

	// delete volumes
	for _, v := range volumes {
		tags, xerr := s.rpcReadTagsOfResource(ctx, v.VolumeID)
		if xerr != nil {
			continue
		}
		if _, ok := tags["DeleteWithVM"]; ok {
			if xerr = s.DeleteVolume(ctx, v.VolumeID); xerr != nil { // continue to delete even if error
				logrus.WithContext(ctx).Errorf("Unable to delete Volume %s of Host %s", v.VolumeID, ahf.Core.ID)
			}
		}
	}

	return lastErr
}

func incrementExpVar(name string) {
	// increase counter
	ts := expvar.Get(name)
	if ts != nil {
		switch casted := ts.(type) {
		case *expvar.Int:
			casted.Add(1)
		case metric.Metric:
			casted.Add(1)
		}
	}
}

// InspectHost returns the host identified by id or updates content of a *abstract.Host
func (s stack) InspectHost(ctx context.Context, hostParam stacks.HostParameter) (ahf *abstract.HostFull, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	incrementExpVar("host.inspections")

	var xerr fail.Error
	ahf, _, xerr = stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return nil, xerr
	}

	var vm osc.Vm
	if ahf.Core.ID != "" {
		vm, xerr = s.rpcReadVMByID(ctx, ahf.Core.ID)
		if xerr != nil {
			return nil, xerr
		}
	} else {
		vm, xerr = s.rpcReadVMByName(ctx, ahf.Core.Name)
		if xerr != nil {
			return nil, xerr
		}
	}

	return ahf, s.complementHost(ctx, ahf, vm)
}

func (s stack) complementHost(ctx context.Context, ahf *abstract.HostFull, vm osc.Vm) fail.Error {
	ahf.Core.ID = vm.VmId

	tags, xerr := s.rpcReadTagsOfResource(ctx, vm.VmId)
	if xerr != nil {
		return xerr
	}

	if ahf.Core.Name == "" {
		if tag, ok := tags["name"]; ok {
			ahf.Core.Name = tag
		}
	}

	// refresh tags
	for k, v := range tags {
		ahf.Core.Tags[k] = v
	}

	subnets, nics, xerr := s.listSubnetsByHost(ctx, vm.VmId)
	if xerr != nil {
		return xerr
	}
	xerr = s.setHostProperties(ctx, ahf, subnets, vm, nics)
	return xerr
}

// GetHostState returns the current state of the host identified by id
func (s stack) GetHostState(ctx context.Context, hostParam stacks.HostParameter) (_ hoststate.Enum, ferr fail.Error) {
	if valid.IsNil(s) {
		return hoststate.Unknown, fail.InvalidInstanceError()
	}

	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return hoststate.Unknown, xerr
	}

	return s.hostState(ctx, ahf.Core.ID)
}

// ListHosts lists all hosts
func (s stack) ListHosts(ctx context.Context, details bool) (_ abstract.HostList, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	resp, xerr := s.rpcReadVMs(ctx, nil)
	if xerr != nil {
		return nil, xerr
	}

	var hosts abstract.HostList
	for _, vm := range resp { // nolint
		now := time.Now()
		if hostState(vm.State) == hoststate.Terminated {
			continue
		}

		state := hostState(vm.State)
		ahf := abstract.NewHostFull()
		ahf.Core.ID = vm.VmId
		ahf.CurrentState, ahf.Core.LastState = state, state
		if details {
			ahf, xerr = s.InspectHost(ctx, ahf)
			if xerr != nil {
				return nil, xerr
			}
		} else {
			tags, xerr := s.rpcReadTagsOfResource(ctx, vm.VmId)
			if xerr != nil {
				return nil, xerr
			}

			if tag, ok := tags["name"]; ok {
				ahf.Core.Name = tag
			}

			// refresh tags
			for k, v := range tags {
				ahf.Core.Tags[k] = v
			}
		}
		hosts = append(hosts, ahf)
		logrus.WithContext(ctx).Debugf("Loading the host took %s", time.Since(now))
	}
	return hosts, nil
}

// StopHost stops the host identified by id
func (s stack) StopHost(ctx context.Context, host stacks.HostParameter, gracefully bool) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, host)
	if xerr != nil {
		return xerr
	}

	return s.rpcStopVMs(ctx, []string{ahf.Core.ID})
}

// StartHost starts the host identified by id
func (s stack) StartHost(ctx context.Context, hostParam stacks.HostParameter) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	return s.rpcStartVMs(ctx, []string{ahf.Core.ID})
}

// RebootHost Reboot host
func (s stack) RebootHost(ctx context.Context, hostParam stacks.HostParameter) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	return s.rpcRebootVMs(ctx, []string{ahf.Core.ID})
}

func (s stack) perfFromFreq(freq float32) int {
	var perfList sort.IntSlice
	for k := range s.CPUPerformanceMap {
		perfList = append(perfList, k)
	}
	sort.Sort(sort.Reverse(perfList))
	for _, perf := range perfList {
		if freq < s.CPUPerformanceMap[perf] {
			return perf
		}
	}
	return 1
}

// BindSecurityGroupToHost ...
func (s stack) BindSecurityGroupToHost(ctx context.Context, sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return xerr
	}
	if !asg.IsConsistent() {
		asg, xerr = s.InspectSecurityGroup(ctx, asg.ID)
		if xerr != nil {
			return xerr
		}
	}

	ahf, hostLabel, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	vm, xerr := s.rpcReadVMByID(ctx, ahf.Core.ID)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to query information of Host %s", hostLabel)
	}

	found := false
	sgs := make([]string, 0, len(vm.SecurityGroups)+1)
	for _, v := range vm.SecurityGroups {
		if v.SecurityGroupId == asg.ID {
			found = true
			break
		}
		sgs = append(sgs, v.SecurityGroupId)
	}
	if found {
		// Security Group already bound to Host
		return nil
	}

	// Add new SG to Host
	sgs = append(sgs, asg.ID)
	return s.rpcUpdateVMSecurityGroups(ctx, ahf.Core.ID, sgs)
}

// UnbindSecurityGroupFromHost ...
func (s stack) UnbindSecurityGroupFromHost(ctx context.Context, sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return xerr
	}
	ahf, hostLabel, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	vm, xerr := s.rpcReadVMByID(ctx, ahf.Core.ID)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// if host is not found, consider operation as a success; continue
			debug.IgnoreError2(ctx, xerr)
			return fail.Wrap(xerr, "failed to query information of Host %s", hostLabel)
		default:
			return fail.Wrap(xerr, "failed to query information of Host %s", hostLabel)
		}
	}

	found := false
	sgs := make([]string, 0, len(vm.SecurityGroups))
	for _, v := range vm.SecurityGroups {
		if v.SecurityGroupId != asg.ID {
			sgs = append(sgs, v.SecurityGroupId)
		} else {
			found = true
		}
	}
	if !found {
		// Security Group not bound to Host, exit gracefully
		return nil
	}

	// Update Security Groups of Host
	return s.rpcUpdateVMSecurityGroups(ctx, ahf.Core.ID, sgs)
}
