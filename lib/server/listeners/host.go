/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
	"github.com/asaskevich/govalidator"

	"google.golang.org/grpc/status"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
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
func (s *HostListener) Start(ctx context.Context, in *pb.Reference) (empty *google_protobuf.Empty, err error) {
	empty = &google_protobuf.Empty{}
	if s == nil {
		return empty, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	ref := srvutils.GetReference(in)
	if ref == "" {
		return empty, scerr.InvalidParameterError("ref", "cannot be empty string").ToGRPCStatus()
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

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := srvutils.JobRegister(ctx, cancelFunc, "Start Host "+in.GetName()); err != nil {
		return empty, status.Errorf(codes.FailedPrecondition, fmt.Errorf("failed to register the process : %s", err.Error()).Error())
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		msg := "cannot start host: no tenant set"
		tracer.Trace(utils.Capitalize(msg))
		return empty, status.Errorf(codes.FailedPrecondition, msg)
	}

	handler := handlers.NewHostHandler(tenant.Service)
	err = handler.Start(ctx, ref)
	if err != nil {
		return empty, scerr.Wrap(err, "cannot start host").ToGRPCStatus()
	}

	tracer.Trace("Host '%s' successfully started", ref)
	return empty, nil
}

// Stop shutdowns a host.
func (s *HostListener) Stop(ctx context.Context, in *pb.Reference) (empty *google_protobuf.Empty, err error) {
	empty = &google_protobuf.Empty{}
	if s == nil {
		return empty, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return empty, scerr.InvalidParameterError("in", "can't be nil").ToGRPCStatus()
	}
	ref := srvutils.GetReference(in)
	if ref == "" {
		return empty, scerr.InvalidRequestError("cannot stop host: neither name nor id of host has been provided").ToGRPCStatus()
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

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// LATER: handle jobregister error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Stop Host "+ref); err == nil {
		defer srvutils.JobDeregister(ctx)
	} /* else {
		return empty, scerr.InvalidInstanceContentError("ctx", "has no uuid").ToGRPCStatus()
	}*/

	tenant := GetCurrentTenant()
	if tenant == nil {
		msg := "cannot stop host: no tenant set"
		tracer.Trace(utils.Capitalize("Cannot stop host: no tenant set"))
		return empty, status.Errorf(codes.FailedPrecondition, msg)
	}

	handler := handlers.NewHostHandler(tenant.Service)
	err = handler.Stop(ctx, ref)
	if err != nil {
		return empty, scerr.Wrap(err, "cannot stop host").ToGRPCStatus()
	}

	tracer.Trace("Host '%s' stopped", ref)
	return empty, nil
}

// Reboot reboots a host.
func (s *HostListener) Reboot(ctx context.Context, in *pb.Reference) (empty *google_protobuf.Empty, err error) {
	empty = &google_protobuf.Empty{}
	if s == nil {
		return empty, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	ref := srvutils.GetReference(in)
	if ref == "" {
		return empty, scerr.InvalidParameterError("ref", "cannot be empty string").ToGRPCStatus()
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

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// LATER: handle jobregister error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Reboot Host "+ref); err == nil {
		defer srvutils.JobDeregister(ctx)
	} /* else {
		return empty, scerr.InvalidInstanceContentError("ctx", "has no uuid").ToGRPCStatus()
	}*/

	tenant := GetCurrentTenant()
	if tenant == nil {
		msg := "cannot reboot host: no tenant set"
		tracer.Trace(utils.Capitalize(msg))
		return empty, status.Errorf(codes.FailedPrecondition, msg)
	}

	handler := handlers.NewHostHandler(tenant.Service)
	err = handler.Reboot(ctx, ref)
	if err != nil {
		return empty, scerr.Wrap(err, "cannot reboot host").ToGRPCStatus()
	}

	tracer.Trace("Host '%s' successfully rebooted.", ref)
	return empty, nil
}

// List lists hosts managed by SafeScale only, or all hosts.
func (s *HostListener) List(ctx context.Context, in *pb.HostListRequest) (hl *pb.HostList, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	all := in.GetAll()

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("(%v)", all), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)

	ctx, cancelFunc := context.WithCancel(ctx)
	// LATER: handle jobregister error
	if err := srvutils.JobRegister(ctx, cancelFunc, "List Hosts"); err == nil {
		defer srvutils.JobDeregister(ctx)
	} /* else {
		return nil, scerr.InvalidInstanceContentError("ctx", "has no uuid").ToGRPCStatus()
	}*/

	tenant := GetCurrentTenant()
	if tenant == nil {
		msg := "cannot list hosts: no tenant set"
		tracer.Trace(utils.Capitalize(msg))
		return nil, status.Errorf(codes.FailedPrecondition, msg)
	}

	handler := handlers.NewHostHandler(tenant.Service)
	hosts, err := handler.List(ctx, all)
	if err != nil {
		return nil, scerr.Wrap(err, "cannot list hosts").ToGRPCStatus()
	}

	// Map resources.Host to pb.Host
	var pbhost []*pb.Host
	for _, host := range hosts {
		pbhost = append(pbhost, srvutils.ToPBHost(host))
	}
	rv := &pb.HostList{Hosts: pbhost}
	return rv, nil
}

// Create creates a new host
func (s *HostListener) Create(ctx context.Context, in *pb.HostDefinition) (h *pb.Host, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "cannot be nil").ToGRPCStatus()
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	name := in.GetName()

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", name), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// LATER: handle jobregister error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Create Host "+in.GetName()); err == nil {
		defer srvutils.JobDeregister(ctx)
	} /* else {
		return nil, scerr.InvalidInstanceContentError("ctx", "has no uuid").ToGRPCStatus()
	}*/

	tenant := GetCurrentTenant()
	if tenant == nil {
		msg := "cannot create host: no tenant set"
		tracer.Trace(utils.Capitalize(msg))
		return nil, status.Errorf(codes.FailedPrecondition, msg)
	}

	var sizing *resources.SizingRequirements
	if in.Sizing == nil {
		sizing = &resources.SizingRequirements{
			MinCores:    int(in.GetCpuCount()),
			MaxCores:    int(in.GetCpuCount()),
			MinRAMSize:  in.GetRam(),
			MaxRAMSize:  in.GetRam(),
			MinDiskSize: int(in.GetDisk()),
			MinGPU:      int(in.GetGpuCount()),
			MinFreq:     in.GetCpuFreq(),
		}
	} else {
		s := srvutils.FromPBHostSizing(*in.Sizing)
		sizing = &s
	}

	handler := handlers.NewHostHandler(tenant.Service)
	host, err := handler.Create(ctx,
		name,
		in.GetNetwork(),
		in.GetImageId(),
		in.GetPublic(),
		sizing,
		in.Force,
	)
	if err != nil {
		return nil, scerr.Wrap(err, "cannot create host").ToGRPCStatus()
	}
	logrus.Infof("Host '%s' created", name)
	return srvutils.ToPBHost(host), nil
}

// Resize an host
func (s *HostListener) Resize(ctx context.Context, in *pb.HostDefinition) (_ *pb.Host, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "cannot be nil").ToGRPCStatus()
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	name := in.GetName()

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", name), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// LATER: handle jobregister error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Resize Host "+name); err == nil {
		defer srvutils.JobDeregister(ctx)
	} /* else {
		return nil, scerr.InvalidInstanceContentError("ctx", "has no uuid").ToGRPCStatus()
	}*/

	tenant := GetCurrentTenant()
	if tenant == nil {
		msg := "cannot resize host: no tenant set"
		tracer.Trace(utils.Capitalize(msg))
		return nil, status.Errorf(codes.FailedPrecondition, msg)
	}

	handler := handlers.NewHostHandler(tenant.Service)
	host, err := handler.Resize(ctx,
		name,
		int(in.GetCpuCount()),
		in.GetRam(),
		int(in.GetDisk()),
		int(in.GetGpuCount()),
		float32(in.GetCpuFreq()),
	)
	if err != nil {
		return nil, scerr.Wrap(err, "cannot resize host").ToGRPCStatus()
	}
	tracer.Trace("Host '%s' successfully resized", name)
	return srvutils.ToPBHost(host), nil
}

// Status returns the status of a host (running or stopped mainly)
func (s *HostListener) Status(ctx context.Context, in *pb.Reference) (ht *pb.HostStatus, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "cannot be nil").ToGRPCStatus()
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
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

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// LATER: handle jobregister error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Status of Host "+in.GetName()); err == nil {
		defer srvutils.JobDeregister(ctx)
	} /* else {
		return nil, scerr.InvalidInstanceContentError("ctx", "has no uuid").ToGRPCStatus()
	}*/

	tenant := GetCurrentTenant()
	if tenant == nil {
		msg := "cannot get host status: no tenant set"
		tracer.Trace(utils.Capitalize(msg))
		return nil, status.Errorf(codes.FailedPrecondition, msg)
	}

	handler := handlers.NewHostHandler(tenant.Service)
	host, err := handler.ForceInspect(ctx, ref)
	if err != nil {
		return nil, scerr.Wrap(err, "cannot get host status").ToGRPCStatus()
	}
	return srvutils.ToHostStatus(host), nil
}

// Inspect an host
func (s *HostListener) Inspect(ctx context.Context, in *pb.Reference) (h *pb.Host, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "cannot be nil").ToGRPCStatus()
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
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

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// LATER: handle jobregister error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Inspect Host "+in.GetName()); err == nil {
		defer srvutils.JobDeregister(ctx)
	} /* else {
		return nil, scerr.InvalidInstanceContentError("ctx", "has no uuid").ToGRPCStatus()
	}*/

	tenant := GetCurrentTenant()
	if tenant == nil {
		msg := "cannot inspect host: no tenant set"
		tracer.Trace(utils.Capitalize(msg))
		return nil, status.Errorf(codes.FailedPrecondition, msg)
	}

	handler := handlers.NewHostHandler(tenant.Service)
	host, err := handler.ForceInspect(ctx, ref)
	if err != nil {
		return nil, scerr.Wrap(err, "cannot inspect host").ToGRPCStatus()
	}
	return srvutils.ToPBHost(host), nil
}

// Delete an host
func (s *HostListener) Delete(ctx context.Context, in *pb.Reference) (empty *google_protobuf.Empty, err error) {
	empty = &google_protobuf.Empty{}
	if s == nil {
		return empty, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return empty, scerr.InvalidParameterError("in", "cannot be nil").ToGRPCStatus()
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

	ref := srvutils.GetReference(in)
	if ref == "" {
		return empty, status.Errorf(codes.FailedPrecondition, "cannot get host status: neither name nor id given as reference")
	}

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// LATER: handle jobregister error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Delete Host "+in.GetName()); err == nil {
		defer srvutils.JobDeregister(ctx)
	} /* else {
		return empty, scerr.InvalidInstanceContentError("ctx", "has no uuid").ToGRPCStatus()
	}*/

	tenant := GetCurrentTenant()
	if tenant == nil {
		msg := "cannot delete host: no tenant set"
		tracer.Trace(utils.Capitalize(msg))
		return empty, status.Errorf(codes.FailedPrecondition, msg)
	}

	handler := handlers.NewHostHandler(tenant.Service)
	err = handler.Delete(ctx, ref)
	if err != nil {
		return empty, scerr.Wrap(err, "cannot delete host").ToGRPCStatus()
	}
	tracer.Trace("Host '%s' successfully deleted.", ref)
	return empty, nil
}

// SSH returns ssh parameters to access an host
func (s *HostListener) SSH(ctx context.Context, in *pb.Reference) (sc *pb.SshConfig, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError().ToGRPCStatus()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "cannot be nil").ToGRPCStatus()
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil").ToGRPCStatus()
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

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// LATER: handle jobregister error
	if err := srvutils.JobRegister(ctx, cancelFunc, "SSH config of Host "+in.GetName()); err == nil {
		defer srvutils.JobDeregister(ctx)
	} /* else {
		return nil, scerr.InvalidInstanceContentError("ctx", "has no uuid").ToGRPCStatus()
	}*/

	tenant := GetCurrentTenant()
	if tenant == nil {
		msg := "cannot get ssh config of host: no tenant set"
		tracer.Trace(utils.Capitalize(msg))
		return nil, status.Errorf(codes.FailedPrecondition, msg)
	}

	handler := handlers.NewHostHandler(currentTenant.Service)
	sshConfig, err := handler.SSH(ctx, ref)
	if err != nil {
		return nil, scerr.Wrap(err, "cannot ssh host").ToGRPCStatus()
	}

	tracer.Trace("SSH config of host '%s' successfully loaded", ref)
	return srvutils.ToPBSshConfig(sshConfig), nil
}
