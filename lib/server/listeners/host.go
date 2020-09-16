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

package listeners

import (
	"context"
	hostfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/host"
	securitygroupfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/securitygroup"
	"reflect"
	"strings"

	"github.com/asaskevich/govalidator"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	hostfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/host"
	networkfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/network"
	securitygroupfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/securitygroup"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// HostListener host service server grpc
type HostListener struct{}

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

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return empty, fail.InvalidParameterError("ref", "cannot be empty string")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), "host start")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.host"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewHostHandler(job)
	err = handler.Start(ref)
	if err != nil {
		return empty, err
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
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
	}
	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return empty, fail.InvalidRequestError("neither name nor id of host has been provided")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), "host stop")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.host"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewHostHandler(job)
	err = handler.Stop(ref)
	if err != nil {
		return empty, err
	}

	tracer.Trace("Host %s stopped", refLabel)
	return empty, nil
}

// Reboot reboots a host.
func (s *HostListener) Reboot(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot reboot host")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil")
	}
	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return empty, fail.InvalidRequestError("neither name nor id of host has been provided")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), "host reboot")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.host"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewHostHandler(job)
	err = handler.Reboot(ref)
	if err != nil {
		return empty, err
	}

	tracer.Trace("Host %s successfully rebooted.", refLabel)
	return empty, nil
}

// List lists hosts managed by SafeScale only, or all hosts.
func (s *HostListener) List(ctx context.Context, in *protocol.HostListRequest) (hl *protocol.HostList, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list hosts")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), "host list")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	all := in.GetAll()
	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.host"), "(%v)", all).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewHostHandler(job)
	hosts, xerr := handler.List(all)
	if xerr != nil {
		return nil, xerr
	}

	// build response mapping abstract.Host to protocol.Host
	var pbhost []*protocol.Host
	for _, host := range hosts {
		pbhost = append(pbhost, converters.HostFullFromAbstractToProtocol(host))
	}
	rv := &protocol.HostList{Hosts: pbhost}
	return rv, nil
}

// Create creates a new host
func (s *HostListener) Create(ctx context.Context, in *protocol.HostDefinition) (_ *protocol.Host, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot create host")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), "host create")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	name := in.GetName()
	task := job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.home"), "('%s')", name).WithStopwatch().Entering()
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
	sizing.Image = in.GetImageId()

	network, xerr := networkfactory.Load(task, job.GetService(), in.GetNetwork())
	if xerr != nil {
		return nil, xerr
	}

	domain := in.Domain
	if domain == "" {
		xerr = network.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
			an, ok := clonable.(*abstract.Network)
			if !ok {
				return fail.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			domain = an.Domain
			return nil
		})
		if xerr != nil {
			return nil, xerr
		}
	}
	domain = strings.Trim(domain, ".")
	if domain != "" {
		domain = "." + domain
	}

	hostReq := abstract.HostRequest{
		ResourceName:  name,
		HostName:      name + domain,
		PublicIP:      in.GetPublic(),
		KeepOnFailure: in.GetKeepOnFailure(),
	}
	err = network.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		networkCore, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		hostReq.Networks = []*abstract.Network{networkCore}
		return nil
	})

	handler := handlers.NewHostHandler(job)
	host, err := handler.Create(hostReq, *sizing, in.Force)
	if err != nil {
		return nil, err
	}
	// logrus.Infof("Host '%s' created", name)
	return host.ToProtocol(task)
}

// Resize an host
func (s *HostListener) Resize(ctx context.Context, in *protocol.HostDefinition) (_ *protocol.Host, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot resize host")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), "host resize")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	name := in.GetName()
	task := job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.host"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewHostHandler(job)
	host, err := handler.Resize(
		name,
		abstract.HostSizingRequirements{
			MinCores:    int(in.GetCpuCount()),
			MinRAMSize:  in.GetRam(),
			MinDiskSize: int(in.GetDisk()),
			MinGPU:      int(in.GetGpuCount()),
			MinCPUFreq:  in.GetCpuFreq(),
		},
	)
	if err != nil {
		return nil, err
	}
	tracer.Trace("Host '%s' successfully resized", name)
	return host.ToProtocol(task)
}

// Status returns the status of a host (running or stopped mainly)
func (s *HostListener) Status(ctx context.Context, in *protocol.Reference) (ht *protocol.HostStatus, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot get host status")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference").ToGRPCStatus()
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), "host state")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	task := job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.host"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewHostHandler(job)
	host, err := handler.Inspect(ref)
	if err != nil {
		return nil, err
	}
	return converters.HostStatusFromAbstractToProtocol(host.GetName(), host.GetState(task)), nil
}

// Inspect an host
func (s *HostListener) Inspect(ctx context.Context, in *protocol.Reference) (h *protocol.Host, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot inspect host")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), "host inspect")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	task := job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.host"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewHostHandler(job)
	host, err := handler.Inspect(ref)
	if err != nil {
		return nil, err
	}
	return host.ToProtocol(task)
}

// Delete an host
func (s *HostListener) Delete(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot delete host")

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

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return empty, status.Errorf(codes.FailedPrecondition, "neither name nor id given as reference")
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), "host delete")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.host"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewHostHandler(job)
	err = handler.Delete(ref)
	if err != nil {
		return empty, err
	}
	tracer.Trace("Host %s successfully deleted.", refLabel)
	return empty, nil
}

// SSH returns ssh parameters to access an host
func (s *HostListener) SSH(ctx context.Context, in *protocol.Reference) (sc *protocol.SshConfig, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot get host SSH information")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), "host ssh")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.host"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewHostHandler(job)
	sshConfig, err := handler.SSH(ref)
	if err != nil {
		return nil, err
	}

	tracer.Trace("SSH config of host %s successfully loaded", refLabel)
	return converters.SSHConfigFromAbstractToProtocol(*sshConfig), nil
}

// BindSecurityGroup attaches a Security Group to an host
func (s *HostListener) BindSecurityGroup(ctx context.Context, in *protocol.SecurityGroupBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot get host SSH information")

	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil && !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
	}

	hostRef, hostRefLabel := srvutils.GetReference(in.GetTarget())
	if hostRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Host")
	}
	sgRef, sgRefLabel := srvutils.GetReference(in.GetGroup())
	if hostRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Security Group")
	}

	job, xerr := PrepareJob(ctx, in.GetGroup().GetTenantId(), "host bind-security-group")
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()
	task := job.GetTask()
	svc := job.GetService()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.host"), "(%s, %s)", hostRefLabel, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rh, xerr := hostfactory.Load(task, svc, hostRef)
	if xerr != nil {
		return empty, xerr
	}
	sg, xerr := securitygroupfactory.Load(task, svc, sgRef)
	if xerr != nil {
		return empty, xerr
	}
	if xerr = rh.BindSecurityGroup(task, sg, in.GetEnabled()); xerr != nil {
		return empty, xerr
	}
	return empty, nil
}

// UnbindSecurityGroup detaches a Security Group from an host
func (s *HostListener) UnbindSecurityGroup(ctx context.Context, in *protocol.SecurityGroupBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot get host SSH information")

	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil && !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	hostRef, hostRefLabel := srvutils.GetReference(in.GetTarget())
	if hostRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference of host")
	}

	sgRef, sgRefLabel := srvutils.GetReference(in.GetGroup())
	if sgRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference of Security Group")
	}

	job, xerr := PrepareJob(ctx, in.GetGroup().GetTenantId(), "host unbind-security-group")
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()
	task := job.GetTask()
	svc := job.GetService()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.host"), "(%s, %s)", hostRefLabel, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rh, xerr := hostfactory.Load(task, svc, hostRef)
	if xerr != nil {
		return empty, xerr
	}
	sg, xerr := securitygroupfactory.Load(task, svc, sgRef)
	if xerr != nil {
		return empty, xerr
	}
	if xerr = rh.UnbindSecurityGroup(task, sg); xerr != nil {
		return empty, xerr
	}
	return empty, nil
}
