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
	"reflect"

	"github.com/asaskevich/govalidator"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	networkfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/network"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
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
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot start host").ToGRPCStatus()
		}
	}()

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, scerr.InvalidInstanceError()
	}
	ref := srvutils.GetReference(in)
	if ref == "" {
		return empty, scerr.InvalidParameterError("ref", "cannot be empty string")
	}
	if ctx == nil {
		return empty, scerr.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, err := PrepareJob(ctx, "", "host start")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.SafeGetTask(), debug.IfTrace("listeners.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	handler := handlers.NewHostHandler(job)
	err = handler.Start(ref)
	if err != nil {
		return empty, err
	}

	tracer.Trace("Host '%s' successfully started", ref)
	return empty, nil
}

// Stop shutdowns a host.
func (s *HostListener) Stop(ctx context.Context, in *protocol.Reference) (empty *google_protobuf.Empty, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot stop host").ToGRPCStatus()
		}
	}()

	empty = &google_protobuf.Empty{}
	if s == nil {
		return empty, scerr.InvalidInstanceError()
	}
	if in == nil {
		return empty, scerr.InvalidParameterError("in", "can't be nil")
	}
	ref := srvutils.GetReference(in)
	if ref == "" {
		return empty, scerr.InvalidRequestError("cannot stop host: neither name nor id of host has been provided")
	}
	if ctx == nil {
		return empty, scerr.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, err := PrepareJob(ctx, "", "host stop")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.SafeGetTask(), debug.IfTrace("listeners.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	handler := handlers.NewHostHandler(job)
	err = handler.Stop(ref)
	if err != nil {
		return empty, err
	}

	tracer.Trace("Host '%s' stopped", ref)
	return empty, nil
}

// Reboot reboots a host.
func (s *HostListener) Reboot(ctx context.Context, in *protocol.Reference) (empty *google_protobuf.Empty, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot reboot host").ToGRPCStatus()
		}
	}()

	empty = &google_protobuf.Empty{}
	if s == nil {
		return empty, scerr.InvalidInstanceError()
	}
	ref := srvutils.GetReference(in)
	if ref == "" {
		return empty, scerr.InvalidParameterError("ref", "cannot be empty string")
	}
	if ctx == nil {
		return empty, scerr.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, err := PrepareJob(ctx, "", "host reboot")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.SafeGetTask(), debug.IfTrace("listeners.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	handler := handlers.NewHostHandler(job)
	err = handler.Reboot(ref)
	if err != nil {
		return empty, err
	}

	tracer.Trace("Host '%s' successfully rebooted.", ref)
	return empty, nil
}

// List lists hosts managed by SafeScale only, or all hosts.
func (s *HostListener) List(ctx context.Context, in *protocol.HostListRequest) (hl *protocol.HostList, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot list hosts").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, err := PrepareJob(ctx, "", "host list")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	all := in.GetAll()
	tracer := concurrency.NewTracer(job.SafeGetTask(), debug.IfTrace("listeners.host"), "(%v)", all).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)

	handler := handlers.NewHostHandler(job)
	hosts, err := handler.List(all)
	if err != nil {
		return nil, err
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
func (s *HostListener) Create(ctx context.Context, in *protocol.HostDefinition) (h *protocol.Host, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot create host").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, err := PrepareJob(ctx, "", "host create")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	name := in.GetName()
	task := job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.IfTrace("listeners.home"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	var sizing *abstract.HostSizingRequirements
	if in.Sizing == nil {
		sizing = &abstract.HostSizingRequirements{
			MinCores:    int(in.GetCpuCount()),
			MaxCores:    int(in.GetCpuCount()),
			MinRAMSize:  in.GetRam(),
			MaxRAMSize:  in.GetRam(),
			MinDiskSize: int(in.GetDisk()),
			MinGPU:      int(in.GetGpuCount()),
			MinCPUFreq:  in.GetCpuFreq(),
			Image:       in.GetImageId(),
		}
	} else {
		s := converters.HostSizingRequirementsFromProtocolToAbstract(*in.Sizing)
		sizing = &s
	}

	network, err := networkfactory.Load(task, job.SafeGetService(), in.GetNetwork())
	if err != nil {
		return nil, err
	}

	hostReq := abstract.HostRequest{
		ResourceName: name,
		PublicIP:     in.GetPublic(),
	}
	err = network.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		networkCore, ok := clonable.(*abstract.Network)
		if !ok {
			return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		hostReq.Networks = []*abstract.Network{networkCore}
		return nil
	})

	handler := handlers.NewHostHandler(job)
	host, err := handler.Create(hostReq, *sizing, in.Force)
	if err != nil {
		return nil, err
	}
	logrus.Infof("Host '%s' created", name)
	return host.ToProtocol(task)
}

// Resize an host
func (s *HostListener) Resize(ctx context.Context, in *protocol.HostDefinition) (_ *protocol.Host, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot resize host").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, err := PrepareJob(ctx, "", "host resize")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	name := in.GetName()
	task := job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.IfTrace("listeners.host"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

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
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot get host status").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	ref := srvutils.GetReference(in)
	if ref == "" {
		return nil, scerr.InvalidRequestError("cannot get host status: neither name nor id given as reference").ToGRPCStatus()
	}

	job, err := PrepareJob(ctx, "", "host state")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	task := job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.IfTrace("listeners.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	handler := handlers.NewHostHandler(job)
	host, err := handler.Inspect(ref)
	if err != nil {
		return nil, err
	}
	return converters.HostStatusFromAbstractToProtocol(host.SafeGetName(), host.SafeGetState(task)), nil
}

// Inspect an host
func (s *HostListener) Inspect(ctx context.Context, in *protocol.Reference) (h *protocol.Host, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot inspect host").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	ref := srvutils.GetReference(in)
	if ref == "" {
		return nil, scerr.InvalidRequestError("neither name nor id given as reference")
	}

	job, err := PrepareJob(ctx, "", "host inspect")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	task := job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.IfTrace("listeners.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	handler := handlers.NewHostHandler(job)
	host, err := handler.Inspect(ref)
	if err != nil {
		return nil, err
	}
	return host.ToProtocol(task)
}

// Delete an host
func (s *HostListener) Delete(ctx context.Context, in *protocol.Reference) (empty *google_protobuf.Empty, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot delete host").ToGRPCStatus()
		}
	}()

	empty = &google_protobuf.Empty{}
	if s == nil {
		return empty, scerr.InvalidInstanceError()
	}
	if in == nil {
		return empty, scerr.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return empty, scerr.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	ref := srvutils.GetReference(in)
	if ref == "" {
		return empty, status.Errorf(codes.FailedPrecondition, "cannot get host status: neither name nor id given as reference")
	}

	job, err := PrepareJob(ctx, "", "host delete")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.SafeGetTask(), debug.IfTrace("listeners.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	handler := handlers.NewHostHandler(job)
	err = handler.Delete(ref)
	if err != nil {
		return empty, err
	}
	tracer.Trace("Host '%s' successfully deleted.", ref)
	return empty, nil
}

// SSH returns ssh parameters to access an host
func (s *HostListener) SSH(ctx context.Context, in *protocol.Reference) (sc *protocol.SshConfig, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot get host ssh config").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	ref := srvutils.GetReference(in)
	if ref == "" {
		return nil, scerr.InvalidRequestError("cannot get ssh config of host: neither name nor id given as reference")
	}

	job, err := PrepareJob(ctx, "", "host ssh")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.SafeGetTask(), debug.IfTrace("listeners.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	handler := handlers.NewHostHandler(job)
	sshConfig, err := handler.SSH(ref)
	if err != nil {
		return nil, err
	}

	tracer.Trace("SSH config of host '%s' successfully loaded", ref)
	return converters.SSHConfigFromAbstractToProtocol(*sshConfig), nil
}
