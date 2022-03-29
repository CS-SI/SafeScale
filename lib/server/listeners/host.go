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

package listeners

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/davecgh/go-spew/spew"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/CS-SI/SafeScale/v21/lib/protocol"
	"github.com/CS-SI/SafeScale/v21/lib/server/handlers"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/securitygroupstate"
	hostfactory "github.com/CS-SI/SafeScale/v21/lib/server/resources/factories/host"
	securitygroupfactory "github.com/CS-SI/SafeScale/v21/lib/server/resources/factories/securitygroup"
	subnetfactory "github.com/CS-SI/SafeScale/v21/lib/server/resources/factories/subnet"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/operations/converters"
	propertiesv2 "github.com/CS-SI/SafeScale/v21/lib/server/resources/properties/v2"
	srvutils "github.com/CS-SI/SafeScale/v21/lib/server/utils"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
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
func (s *HostListener) Start(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot start host")
	defer fail.OnPanic(&err)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return empty, fail.InvalidParameterError("ref", "cannot be empty string")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("ctx")
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/host/%s/start", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.host"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(job.Context(), job.Service(), ref)
	if xerr != nil {
		return empty, xerr
	}

	defer func() {
		issue := hostInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	xerr = hostInstance.Start(job.Context())
	if xerr != nil {
		return empty, xerr
	}

	tracer.Trace("Host '%s' successfully started", refLabel)
	return empty, nil
}

// Stop shutdowns a host.
func (s *HostListener) Stop(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot stop host")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("ctx").ToGRPCStatus()
	}
	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return empty, fail.InvalidRequestError("neither name nor id of host has been provided")
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/host/%s/stop", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.host"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(job.Context(), job.Service(), ref)
	if xerr != nil {
		return empty, xerr
	}

	defer func() {
		issue := hostInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	if xerr = hostInstance.Stop(job.Context()); xerr != nil {
		return empty, xerr
	}

	tracer.Trace("Host %s stopped", refLabel)
	return empty, nil
}

// Reboot reboots a host.
func (s *HostListener) Reboot(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot reboot host")
	defer fail.OnPanic(&err)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("ctx")
	}
	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return empty, fail.InvalidRequestError("neither name nor id of host has been provided")
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/host%s/reboot", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.host"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(job.Context(), job.Service(), ref)
	if xerr != nil {
		return empty, xerr
	}

	defer func() {
		issue := hostInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	if xerr = hostInstance.Reboot(job.Context(), false); xerr != nil { // FIXME: We should run a sync first
		return empty, xerr
	}

	tracer.Trace("Host %s successfully rebooted.", refLabel)
	return empty, nil
}

// List lists hosts managed by SafeScale only, or all hosts.
func (s *HostListener) List(ctx context.Context, in *protocol.HostListRequest) (hl *protocol.HostList, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list hosts")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), "/hosts/list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	all := in.GetAll()
	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.host"), "(%v)", all).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	// handler := handlers.NewHostHandler(job)
	// hosts, xerr := handler.List(all)
	hosts, xerr := hostfactory.List(job.Context(), job.Service(), all)
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
func (s *HostListener) Create(ctx context.Context, in *protocol.HostDefinition) (_ *protocol.Host, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot create host")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	name := in.GetName()
	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/host/%s/create", name))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.home"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

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
			subnetInstance, xerr = subnetfactory.Load(job.Context(), job.Service(), networkRef, v)
			if xerr != nil {
				return nil, xerr
			}

			//goland:noinspection GoDeferInLoop
			defer func(instance resources.Subnet) { // nolint
				issue := instance.Released()
				if issue != nil {
					logrus.Warn(issue)
				}
			}(subnetInstance)

			xerr = subnetInstance.Review(
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
		subnetInstance, xerr = subnetfactory.Load(job.Context(), job.Service(), networkRef, networkRef)
		if xerr != nil {
			return nil, xerr
		}

		defer func() {
			issue := subnetInstance.Released()
			if issue != nil {
				logrus.Warn(issue)
			}
		}()

		xerr = subnetInstance.Review(
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

	hostInstance, xerr := hostfactory.New(job.Service())
	if xerr != nil {
		return nil, xerr
	}

	_, xerr = hostInstance.Create(job.Context(), hostReq, *sizing)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		issue := hostInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	// logrus.Infof("Host '%s' created", name)
	return hostInstance.ToProtocol(job.Context())
}

// Resize a host
func (s *HostListener) Resize(ctx context.Context, in *protocol.HostDefinition) (_ *protocol.Host, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot resize host")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	name := in.GetName()
	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/host/%s/resize", name))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.host"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	sizing := abstract.HostSizingRequirements{
		MinCores:    int(in.GetCpuCount()),
		MinRAMSize:  in.GetRam(),
		MinDiskSize: int(in.GetDisk()),
		MinGPU:      int(in.GetGpuCount()),
		MinCPUFreq:  in.GetCpuFreq(),
	}

	hostInstance, xerr := hostfactory.Load(job.Context(), job.Service(), name)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		issue := hostInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	reduce := false
	xerr = hostInstance.Inspect(
		func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Inspect(
				hostproperty.SizingV2, func(clonable data.Clonable) fail.Error {
					hostSizingV2, ok := clonable.(*propertiesv2.HostSizing)
					if !ok {
						return fail.InconsistentError(
							"'*propertiesv1.HostSizing' expected, '%s' provided", reflect.TypeOf(clonable).String(),
						)
					}

					reduce = reduce || (sizing.MinCores < hostSizingV2.RequestedSize.MinCores)
					reduce = reduce || (sizing.MinRAMSize < hostSizingV2.RequestedSize.MinRAMSize)
					reduce = reduce || (sizing.MinGPU < hostSizingV2.RequestedSize.MinGPU)
					reduce = reduce || (sizing.MinCPUFreq < hostSizingV2.RequestedSize.MinCPUFreq)
					reduce = reduce || (sizing.MinDiskSize < hostSizingV2.RequestedSize.MinDiskSize)
					return nil
				},
			)
		},
	)
	if xerr != nil {
		return nil, xerr
	}
	if reduce {
		logrus.Warn("Asking for less resource... is not going to happen")
	}

	if xerr = hostInstance.Resize(job.Context(), sizing); xerr != nil {
		return nil, xerr
	}

	tracer.Trace("Host '%s' successfully resized", name)
	return hostInstance.ToProtocol(job.Context())
}

// Status returns the status of a host (running or stopped mainly)
func (s *HostListener) Status(ctx context.Context, in *protocol.Reference) (ht *protocol.HostStatus, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot get host status")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference").ToGRPCStatus()
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/host/%s/state", ref))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.host"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(job.Context(), job.Service(), ref)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return nil, abstract.ResourceNotFoundError("host", ref)
		default:
			return nil, xerr
		}
	}

	defer func() {
		issue := hostInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	// Data sync
	xerr = hostInstance.Reload(job.Context())
	if xerr != nil {
		return nil, xerr
	}

	// Gather host state from Cloud Provider
	state, xerr := hostInstance.ForceGetState(ctx)
	if xerr != nil {
		return nil, xerr
	}

	return converters.HostStatusFromAbstractToProtocol(hostInstance.GetName(), state), nil
}

// Inspect a host
func (s *HostListener) Inspect(ctx context.Context, in *protocol.Reference) (h *protocol.Host, ferr error) {
	defer fail.OnExitConvertToGRPCStatus(&ferr)
	defer fail.OnExitWrapError(&ferr, "cannot inspect host")
	defer fail.OnPanic(&ferr)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}

	ref, _ := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/host/%s/inspect", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()
	jobCtx := job.Context()

	hostInstance, xerr := hostfactory.Load(jobCtx, job.Service(), ref)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return nil, abstract.ResourceNotFoundError("host", ref)
		default:
			return nil, xerr
		}
	}

	defer func() {
		issue := hostInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	_, xerr = hostInstance.ForceGetState(jobCtx)
	if xerr != nil {
		return nil, xerr
	}

	var ph *protocol.Host
	ph, xerr = hostInstance.ToProtocol(job.Context())
	if xerr != nil {
		return nil, xerr
	}

	return ph, nil
}

// Delete a host
func (s *HostListener) Delete(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot delete host")
	defer fail.OnPanic(&err)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return empty, status.Errorf(codes.FailedPrecondition, "neither name nor id given as reference")
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/host/%s/delete", ref))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.host"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(job.Context(), job.Service(), ref)
	if xerr != nil {
		return empty, xerr
	}

	xerr = hostInstance.Delete(job.Context())
	if xerr != nil {
		issue := hostInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
		return empty, xerr
	}

	tracer.Trace("Host %s successfully deleted.", refLabel)
	return empty, nil
}

// SSH returns ssh parameters to access a host
func (s *HostListener) SSH(ctx context.Context, in *protocol.Reference) (sc *protocol.SshConfig, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot get host SSH information")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/host/%s/sshconfig", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.host"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	sshHandler := handlers.NewSSHHandler(job)
	sshConfig, xerr := sshHandler.GetConfig(ref)
	if xerr != nil {
		return nil, xerr
	}

	tracer.Trace("SSH config of host %s successfully loaded: %s", refLabel, spew.Sdump(sshConfig))
	return converters.SSHConfigFromAbstractToProtocol(*sshConfig), nil
}

// BindSecurityGroup attaches a Security Group to a host
func (s *HostListener) BindSecurityGroup(ctx context.Context, in *protocol.SecurityGroupHostBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot bind Security Group to Host")
	defer fail.OnPanic(&err)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil")
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
		ctx, in.GetGroup().GetTenantId(), fmt.Sprintf("/host/%s/securitygroup/%s/bind", hostRef, sgRef),
	)
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.host"), "(%s, %s)", hostRefLabel, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(job.Context(), job.Service(), hostRef)
	if xerr != nil {
		return empty, xerr
	}

	defer func() {
		issue := hostInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	sgInstance, xerr := securitygroupfactory.Load(job.Context(), job.Service(), sgRef)
	if xerr != nil {
		return empty, xerr
	}

	defer func() {
		issue := sgInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	var enable resources.SecurityGroupActivation
	switch in.GetState() {
	case protocol.SecurityGroupState_SGS_DISABLED:
		enable = resources.SecurityGroupDisable
	default:
		enable = resources.SecurityGroupEnable
	}

	if xerr = hostInstance.BindSecurityGroup(job.Context(), sgInstance, enable); xerr != nil {
		return empty, xerr
	}
	return empty, nil
}

// UnbindSecurityGroup detaches a Security Group from a host
func (s *HostListener) UnbindSecurityGroup(ctx context.Context, in *protocol.SecurityGroupHostBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot unbind Security Group from Host")
	defer fail.OnPanic(&err)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil")
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
		ctx, in.GetGroup().GetTenantId(), fmt.Sprintf("/host/%s/securitygroup/%s/unbind", hostRef, sgRef),
	)
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.host"), "(%s, %s)", hostRefLabel, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(job.Context(), job.Service(), hostRef)
	if xerr != nil {
		return empty, xerr
	}

	defer func() {
		issue := hostInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	sgInstance, xerr := securitygroupfactory.Load(job.Context(), job.Service(), sgRef)
	if xerr != nil {
		return empty, xerr
	}

	defer func() {
		issue := sgInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	return empty, hostInstance.UnbindSecurityGroup(job.Context(), sgInstance)
}

// EnableSecurityGroup applies a Security Group already attached (if not already applied)
func (s *HostListener) EnableSecurityGroup(ctx context.Context, in *protocol.SecurityGroupHostBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot enable Security Group on Host")
	defer fail.OnPanic(&err)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil")
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
		ctx, in.GetHost().GetTenantId(), fmt.Sprintf("/host/%s/securitygroup/%s/enable", hostRef, sgRef),
	)
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.host"), "(%s, %s)", hostRefLabel, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(job.Context(), job.Service(), hostRef)
	if xerr != nil {
		return empty, xerr
	}

	defer func() {
		issue := hostInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	sgInstance, xerr := securitygroupfactory.Load(job.Context(), job.Service(), sgRef)
	if xerr != nil {
		return empty, xerr
	}

	defer func() {
		issue := sgInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	if xerr = hostInstance.EnableSecurityGroup(job.Context(), sgInstance); xerr != nil {
		return empty, xerr
	}

	return empty, nil
}

// DisableSecurityGroup applies a Security Group already attached (if not already applied)
func (s *HostListener) DisableSecurityGroup(ctx context.Context, in *protocol.SecurityGroupHostBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot disable security group on host")
	defer fail.OnPanic(&err)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil")
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
		ctx, in.GetHost().GetTenantId(), fmt.Sprintf("/host/%s/securitygroup/%s/disable", hostRef, sgRef),
	)
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.host"), "(%s, %s)", hostRefLabel, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(job.Context(), job.Service(), hostRef)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// considered as a success
			debug.IgnoreError(xerr)
			return empty, nil
		default:
			return empty, xerr
		}
	}

	defer func() {
		issue := hostInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	sgInstance, xerr := securitygroupfactory.Load(job.Context(), job.Service(), sgRef)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// considered as a success
			debug.IgnoreError(xerr)
			return empty, nil
		default:
			return empty, xerr
		}
	}

	defer func() {
		issue := sgInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	if xerr = hostInstance.DisableSecurityGroup(job.Context(), sgInstance); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// considered as a success
			debug.IgnoreError(xerr)
			return empty, nil
		default:
			return empty, xerr
		}
	}

	return empty, nil
}

// ListSecurityGroups applies a Security Group already attached (if not already applied)
func (s *HostListener) ListSecurityGroups(ctx context.Context, in *protocol.SecurityGroupHostBindRequest) (_ *protocol.SecurityGroupBondsResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot disable security group on host")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	hostRef, hostRefLabel := srvutils.GetReference(in.GetHost())
	if hostRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference of Host")
	}

	job, xerr := PrepareJob(ctx, in.GetHost().GetTenantId(), fmt.Sprintf("/host/%s/securitygroups/list", hostRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.host"), "(%s)", hostRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	hostInstance, xerr := hostfactory.Load(job.Context(), job.Service(), hostRef)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		issue := hostInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	bonds, xerr := hostInstance.ListSecurityGroups(securitygroupstate.All)
	if xerr != nil {
		return nil, xerr
	}

	resp := converters.SecurityGroupBondsFromPropertyToProtocol(bonds, "hosts")
	return resp, nil
}
