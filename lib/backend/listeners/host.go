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

package listeners

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/davecgh/go-spew/spew"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/CS-SI/SafeScale/v22/lib/backend/handlers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	subnetfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/subnet"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	srvutils "github.com/CS-SI/SafeScale/v22/lib/backend/utils"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// HostListener host service server grpc
type HostListener struct {
	protocol.UnimplementedHostServiceServer
}

// StoredCPUInfo ...
type StoredCPUInfo struct {
	ID           string `bow:"key"`
	TenantName   string `json:"tenant_name,omitempty"`
	TemplateID   string `json:"template_id,omitempty"`
	TemplateName string `json:"template_name,omitempty"`
	ImageID      string `json:"image_id,omitempty"`
	ImageName    string `json:"image_name,omitempty"`
	LastUpdated  string `json:"last_updated,omitempty"`

	NumberOfCPU    int     `json:"number_of_cpu,omitempty"`
	NumberOfCore   int     `json:"number_of_core,omitempty"`
	NumberOfSocket int     `json:"number_of_socket,omitempty"`
	CPUFrequency   float64 `json:"cpu_frequency,omitempty"`
	CPUArch        string  `json:"cpu_arch,omitempty"`
	Hypervisor     string  `json:"hypervisor,omitempty"`
	CPUModel       string  `json:"cpu_model,omitempty"`
	RAMSize        float64 `json:"ram_size,omitempty"`
	RAMFreq        float64 `json:"ram_freq,omitempty"`
	GPU            int     `json:"gpu,omitempty"`
	GPUModel       string  `json:"gpu_model,omitempty"`
}

// Start ...
func (s *HostListener) Start(inctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot start host")
	defer fail.OnPanic(&err)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return empty, fail.InvalidParameterError("ref", "cannot be empty string")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("inctx")
	}

	job, xerr := PrepareJob(inctx, in.GetTenantId(), fmt.Sprintf("/host/%s/start", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.host"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewHostHandler(job)
	return empty, handler.Start(ref)
}

// Stop shutdowns a host.
func (s *HostListener) Stop(inctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot stop host")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("inctx").ToGRPCStatus()
	}
	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return empty, fail.InvalidRequestError("neither name nor id of host has been provided")
	}

	job, xerr := PrepareJob(inctx, in.GetTenantId(), fmt.Sprintf("/host/%s/stop", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.host"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewHostHandler(job)
	return empty, handler.Stop(ref)
}

// Reboot reboots a host.
func (s *HostListener) Reboot(inctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot reboot host")
	defer fail.OnPanic(&err)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("inctx")
	}
	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return empty, fail.InvalidRequestError("neither name nor id of host has been provided")
	}

	job, xerr := PrepareJob(inctx, in.GetTenantId(), fmt.Sprintf("/host%s/reboot", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.host"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewHostHandler(job)
	return empty, handler.Reboot(ref)
}

// List lists hosts managed by SafeScale only, or all hosts.
func (s *HostListener) List(inctx context.Context, in *protocol.HostListRequest) (hl *protocol.HostList, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot list hosts")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	job, xerr := PrepareJob(inctx, in.GetTenantId(), "/hosts/list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	all := in.GetAll()
	ctx := job.Context()

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.host"), "(%v)", all).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewHostHandler(job)
	hosts, xerr := handler.List(all)
	if xerr != nil {
		return nil, xerr
	}

	// build response mapping abstract.IPAddress to protocol.IPAddress
	pbhost := make([]*protocol.Host, len(hosts))
	for k, host := range hosts {
		pbhost[k] = converters.HostFullFromAbstractToProtocol(host)
	}
	out := &protocol.HostList{Hosts: pbhost}
	return out, nil
}

// Create creates a new host
func (s *HostListener) Create(inctx context.Context, in *protocol.HostDefinition) (_ *protocol.Host, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot create host")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	name := in.GetName()
	job, xerr := PrepareJob(inctx, in.GetTenantId(), fmt.Sprintf("/host/%s/create", name))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.home"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	var sizing *abstract.HostSizingRequirements
	if in.SizingAsString != "" {
		sizing, _, err = converters.HostSizingRequirementsFromStringToAbstract(in.SizingAsString)
		if err != nil {
			return nil, err
		}
	} else if in.Sizing != nil {
		sizing = converters.HostSizingRequirementsFromProtocolToAbstract(in.Sizing)
	}
	if sizing == nil {
		sizing = &abstract.HostSizingRequirements{MinGPU: -1}
	}

	// Determine if the Subnet(s) to use exist
	// Because of legacy, the subnet can be fully identified by network+subnet, or can be identified by network+network,
	// because previous release of SafeScale created network AND subnet with the same name
	var (
		networkRef     string
		subnetInstance resources.Subnet
		subnets        []*abstract.Subnet
	)
	if !in.GetSingle() {
		networkRef = in.GetNetwork()
	}
	if len(in.GetSubnets()) > 0 {
		for _, v := range in.GetSubnets() {
			subnetInstance, xerr = subnetfactory.Load(ctx, job.Service(), networkRef, v)
			if xerr != nil {
				return nil, xerr
			}

			xerr = subnetInstance.Review(ctx,
				func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
					as, ok := clonable.(*abstract.Subnet)
					if !ok {
						return fail.InconsistentError(
							"'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String(),
						)
					}

					subnets = append(subnets, as)
					return nil
				},
			)
			if xerr != nil {
				return nil, xerr
			}
		}
	}
	if len(subnets) == 0 && networkRef != "" {
		subnetInstance, xerr = subnetfactory.Load(ctx, job.Service(), networkRef, networkRef)
		if xerr != nil {
			return nil, xerr
		}

		xerr = subnetInstance.Review(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
			as, ok := clonable.(*abstract.Subnet)
			if !ok {
				return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			subnets = append(subnets, as)
			return nil
		})
		if xerr != nil {
			return nil, xerr
		}
	}
	if len(subnets) == 0 && !in.GetSingle() {
		return nil, fail.InvalidRequestError("insufficient use of --network and/or --subnet or missing --single")
	}

	domain := in.Domain
	domain = strings.Trim(domain, ".")
	if domain != "" {
		domain = "." + domain
	}

	hostReq := abstract.HostRequest{
		ResourceName:  name,
		HostName:      name + domain,
		Single:        in.GetSingle(),
		KeepOnFailure: in.GetKeepOnFailure(),
		Subnets:       subnets,
		ImageRef:      in.GetImageId(),
		DiskSize:      int(in.GetDisk()),
	}

	handler := handlers.NewHostHandler(job)
	hostInstance, xerr := handler.Create(hostReq, *sizing)
	if xerr != nil {
		return nil, xerr
	}

	return hostInstance.ToProtocol(ctx)
}

// Status returns the status of a host (running or stopped mainly)
func (s *HostListener) Status(inctx context.Context, in *protocol.Reference) (ht *protocol.HostStatus, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot get host status")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference").ToGRPCStatus()
	}

	job, err := PrepareJob(inctx, in.GetTenantId(), fmt.Sprintf("/host/%s/state", ref))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.host"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewHostHandler(job)
	state, xerr := handler.Status(ref)
	// in case of error (xerr != nil), returned state is Unknown and can be converted
	return converters.HostStatusFromAbstractToProtocol(ref, state), xerr
}

// Inspect a host
func (s *HostListener) Inspect(inctx context.Context, in *protocol.Reference) (h *protocol.Host, ferr error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &ferr)
	defer fail.OnExitWrapError(inctx, &ferr, "cannot inspect host")
	defer fail.OnPanic(&ferr)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterError("inctx", "cannot be nil")
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}

	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, xerr := PrepareJob(inctx, in.GetTenantId(), fmt.Sprintf("/host/%s/inspect", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.host"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage())

	handler := handlers.NewHostHandler(job)
	hostInstance, xerr := handler.Inspect(ref)
	if xerr != nil {
		return nil, xerr
	}

	var out *protocol.Host
	out, xerr = hostInstance.ToProtocol(ctx)
	if xerr != nil {
		return nil, xerr
	}

	return out, nil
}

// Delete a host
func (s *HostListener) Delete(inctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot delete host")
	defer fail.OnPanic(&err)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return empty, status.Errorf(codes.FailedPrecondition, "neither name nor id given as reference")
	}

	job, err := PrepareJob(inctx, in.GetTenantId(), fmt.Sprintf("/host/%s/delete", ref))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	ctx := job.Context()

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.host"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewHostHandler(job)
	return empty, handler.Delete(ref)
}

// SSH returns ssh parameters to access a host
func (s *HostListener) SSH(inctx context.Context, in *protocol.Reference) (_ *protocol.SshConfig, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot get host SSH information")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, xerr := PrepareJob(inctx, in.GetTenantId(), fmt.Sprintf("/host/%s/sshconfig", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.host"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	sshHandler := handlers.NewSSHHandler(job)
	sshConfig, xerr := sshHandler.GetConfig(ref)
	if xerr != nil {
		return nil, xerr
	}

	tracer.Trace("SSH config of host %s successfully loaded: %s", refLabel, spew.Sdump(sshConfig))
	cfg, xerr := sshConfig.Config()
	if xerr != nil {
		return nil, xerr
	}
	return converters.SSHConfigFromAbstractToProtocol(cfg), nil
}

// BindSecurityGroup attaches a Security Group to a host
func (s *HostListener) BindSecurityGroup(inctx context.Context, in *protocol.SecurityGroupHostBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot bind Security Group to Host")
	defer fail.OnPanic(&err)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	hostRef, hostRefLabel := srvutils.GetReference(in.GetHost())
	if hostRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Host")
	}

	sgRef, sgRefLabel := srvutils.GetReference(in.GetGroup())
	if hostRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Security Group")
	}

	job, xerr := PrepareJob(
		inctx, in.GetGroup().GetTenantId(), fmt.Sprintf("/host/%s/securitygroup/%s/bind", hostRef, sgRef),
	)
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.host"), "(%s, %s)", hostRefLabel, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	var enable resources.SecurityGroupActivation
	switch in.GetState() {
	case protocol.SecurityGroupState_SGS_DISABLED:
		enable = resources.SecurityGroupDisable
	default:
		enable = resources.SecurityGroupEnable
	}

	handler := handlers.NewHostHandler(job)
	return empty, handler.BindSecurityGroup(hostRef, sgRef, enable)
}

// UnbindSecurityGroup detaches a Security Group from a host
func (s *HostListener) UnbindSecurityGroup(inctx context.Context, in *protocol.SecurityGroupHostBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot unbind Security Group from Host")
	defer fail.OnPanic(&err)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	hostRef, hostRefLabel := srvutils.GetReference(in.GetHost())
	if hostRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference of host")
	}

	sgRef, sgRefLabel := srvutils.GetReference(in.GetGroup())
	if sgRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference of Security Group")
	}

	job, xerr := PrepareJob(
		inctx, in.GetGroup().GetTenantId(), fmt.Sprintf("/host/%s/securitygroup/%s/unbind", hostRef, sgRef),
	)
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.host"), "(%s, %s)", hostRefLabel, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewHostHandler(job)
	return empty, handler.UnbindSecurityGroup(hostRef, sgRef)
}

// EnableSecurityGroup applies a Security Group already attached (if not already applied)
func (s *HostListener) EnableSecurityGroup(inctx context.Context, in *protocol.SecurityGroupHostBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot enable Security Group on Host")
	defer fail.OnPanic(&err)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	hostRef, hostRefLabel := srvutils.GetReference(in.GetHost())
	if hostRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference of host")
	}

	sgRef, sgRefLabel := srvutils.GetReference(in.GetGroup())
	if sgRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference of Security Group")
	}

	job, xerr := PrepareJob(inctx, in.GetHost().GetTenantId(), fmt.Sprintf("/host/%s/securitygroup/%s/enable", hostRef, sgRef))
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.host"), "(%s, %s)", hostRefLabel, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewHostHandler(job)
	return empty, handler.EnableSecurityGroup(hostRef, sgRef)
}

// DisableSecurityGroup applies a Security Group already attached (if not already applied)
func (s *HostListener) DisableSecurityGroup(inctx context.Context, in *protocol.SecurityGroupHostBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot disable security group on host")
	defer fail.OnPanic(&err)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	hostRef, hostRefLabel := srvutils.GetReference(in.GetHost())
	if hostRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference of host")
	}

	sgRef, sgRefLabel := srvutils.GetReference(in.GetGroup())
	if sgRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference of Security Group")
	}

	job, xerr := PrepareJob(inctx, in.GetHost().GetTenantId(), fmt.Sprintf("/host/%s/securitygroup/%s/disable", hostRef, sgRef))
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.host"), "(%s, %s)", hostRefLabel, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewHostHandler(job)
	return empty, handler.EnableSecurityGroup(hostRef, sgRef)
}

// ListSecurityGroups applies a Security Group already attached (if not already applied)
func (s *HostListener) ListSecurityGroups(inctx context.Context, in *protocol.SecurityGroupHostBindRequest) (_ *protocol.SecurityGroupBondsResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot disable security group on host")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	hostRef, hostRefLabel := srvutils.GetReference(in.GetHost())
	if hostRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference of Host")
	}

	job, xerr := PrepareJob(inctx, in.GetHost().GetTenantId(), fmt.Sprintf("/host/%s/securitygroups/list", hostRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.host"), "(%s)", hostRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewHostHandler(job)
	bonds, xerr := handler.ListSecurityGroups(hostRef)
	if xerr != nil {
		return nil, xerr
	}

	resp := converters.SecurityGroupBondsFromPropertyToProtocol(bonds, "hosts")
	return resp, nil
}

// ListLabels lists Label/Tag bound to a Host
func (s *HostListener) ListLabels(inctx context.Context, in *protocol.LabelBoundsRequest) (_ *protocol.LabelListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot bind Label to Host")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx").ToGRPCStatus()
	}

	hostRef, hostRefLabel := srvutils.GetReference(in.GetHost())
	if hostRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference of Host")
	}

	kind := strings.ToLower(kindToString(in.GetTags()))
	job, xerr := PrepareJob(inctx, in.GetHost().GetTenantId(), fmt.Sprintf("/host/%s/%s/list", hostRef, kind))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.host"), "(%s, kind=%s)", hostRefLabel, kind).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	hostHandler := handlers.NewHostHandler(job)
	list, xerr := hostHandler.ListLabels(hostRef, kind)
	if xerr != nil {
		return nil, xerr
	}

	out := &protocol.LabelListResponse{
		Labels: list,
	}
	return out, nil
}

func kindToString(state bool) string {
	if state {
		return "Tag"
	}

	return "Label"
}

// InspectLabel inspects a Label of a Host
func (s *HostListener) InspectLabel(inctx context.Context, in *protocol.HostLabelRequest) (_ *protocol.HostLabelResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot inspect Label of Host")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx").ToGRPCStatus()
	}

	hostRef, hostRefLabel := srvutils.GetReference(in.GetHost())
	if hostRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference of Host")
	}

	labelRef, labelRefLabel := srvutils.GetReference(in.GetLabel())
	if labelRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference of Label")
	}

	job, xerr := PrepareJob(inctx, in.GetHost().GetTenantId(), fmt.Sprintf("/host/%s/label/%s/bind", hostRef, labelRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.host"), "(%s, %s)", hostRefLabel, labelRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	hostHandler := handlers.NewHostHandler(job)
	labelInstance, hostValue, xerr := hostHandler.InspectLabel(hostRef, labelRef)
	if xerr != nil {
		return nil, xerr
	}

	pbLabel, xerr := labelInstance.ToProtocol(ctx, false)
	if xerr != nil {
		return nil, xerr
	}

	out := &protocol.HostLabelResponse{
		Id:           pbLabel.Id,
		Name:         pbLabel.Name,
		HasDefault:   pbLabel.HasDefault,
		DefaultValue: pbLabel.DefaultValue,
		Value:        hostValue,
	}
	return out, nil
}

// BindLabel binds a Label to a Host
func (s *HostListener) BindLabel(inctx context.Context, in *protocol.LabelBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot bind Label to Host")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("inctx").ToGRPCStatus()
	}

	hostRef, hostRefLabel := srvutils.GetReference(in.GetHost())
	if hostRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference of Host")
	}

	labelRef, labelRefLabel := srvutils.GetReference(in.GetLabel())
	if labelRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference of Label")
	}

	job, xerr := PrepareJob(inctx, in.GetHost().GetTenantId(), fmt.Sprintf("/host/%s/label/%s/bind", hostRef, labelRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.host"), "(%s, %s)", hostRefLabel, labelRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	hostHandler := handlers.NewHostHandler(job)
	xerr = hostHandler.BindLabel(hostRef, labelRef, in.GetValue())
	if xerr != nil {
		return empty, xerr
	}

	tracer.Trace("Label %s successfully bound to Host %s", labelRefLabel, hostRefLabel)
	return empty, nil
}

// UnbindLabel unbinds a Label from a Host
func (s *HostListener) UnbindLabel(inctx context.Context, in *protocol.LabelBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot unbind Label from Host")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("inctx").ToGRPCStatus()
	}

	hostRef, hostRefLabel := srvutils.GetReference(in.GetHost())
	if hostRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference of Host")
	}

	labelRef, labelRefLabel := srvutils.GetReference(in.GetLabel())
	if labelRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference of Label")
	}

	job, xerr := PrepareJob(inctx, in.GetHost().GetTenantId(), fmt.Sprintf("/host/%s/label/%s/unbind", hostRef, labelRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.host"), "(%s, %s)", hostRefLabel, labelRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	hostHandler := handlers.NewHostHandler(job)
	xerr = hostHandler.UnbindLabel(hostRef, labelRef)
	if xerr != nil {
		return empty, xerr
	}

	tracer.Trace("Label %s successfully unbound from Host %s", hostRefLabel, labelRefLabel)
	return empty, nil
}

// UpdateLabel updates Label value for the Host
func (s *HostListener) UpdateLabel(inctx context.Context, in *protocol.LabelBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot bind Label to Host")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("inctx").ToGRPCStatus()
	}

	hostRef, hostRefLabel := srvutils.GetReference(in.GetHost())
	if hostRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference of Host")
	}

	labelRef, labelRefLabel := srvutils.GetReference(in.GetLabel())
	if labelRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference of Label")
	}

	job, xerr := PrepareJob(inctx, in.GetHost().GetTenantId(), fmt.Sprintf("/host/%s/label/%s/update", hostRef, labelRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.host"), "(%s, %s)", hostRefLabel, labelRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	hostHandler := handlers.NewHostHandler(job)
	xerr = hostHandler.UpdateLabel(hostRef, labelRef, in.GetValue())
	if xerr != nil {
		return empty, xerr
	}

	tracer.Trace("Value of Label %s successfully updated for Host %s", labelRefLabel, hostRefLabel)
	return empty, nil
}

// ResetLabel restores default value of Label to the Host
func (s *HostListener) ResetLabel(inctx context.Context, in *protocol.LabelBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot unbind Label from Host")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("inctx").ToGRPCStatus()
	}

	hostRef, hostRefLabel := srvutils.GetReference(in.GetHost())
	if hostRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference of Host")
	}

	labelRef, labelRefLabel := srvutils.GetReference(in.GetLabel())
	if labelRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference of Label")
	}

	job, xerr := PrepareJob(inctx, in.GetHost().GetTenantId(), fmt.Sprintf("/host/%s/label/%s/reset", hostRef, labelRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.host"), "(%s, %s)", hostRefLabel, labelRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	hostHandler := handlers.NewHostHandler(job)
	xerr = hostHandler.ResetLabel(hostRef, labelRef)
	if xerr != nil {
		return empty, xerr
	}

	tracer.Trace("Value of Label %s for Host %s successfully reset to Label default value", hostRefLabel, labelRefLabel)
	return empty, nil
}
