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

	"google.golang.org/grpc/status"

	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc/codes"

	log "github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// HostHandler ...
var HostHandler = handlers.NewHostHandler

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
func (s *HostListener) Start(ctx context.Context, in *pb.Reference) (empty *googleprotobuf.Empty, err error) {
	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, status.Errorf(codes.FailedPrecondition, scerr.InvalidInstanceError().Error())
	}
	ref := srvutils.GetReference(in)
	if ref == "" {
		return empty, status.Errorf(codes.FailedPrecondition, scerr.InvalidParameterError("ref", "cannot be empty string").Error())
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
		log.Info("Can't start host: no tenant set")
		return empty, status.Errorf(codes.FailedPrecondition, "cannot start host: no tenant set")
	}

	handler := HostHandler(tenant.Service)
	err = handler.Start(ctx, ref)
	if err != nil {
		return empty, status.Errorf(codes.Internal, err.Error())
	}

	log.Infof("Host '%s' successfully started", ref)
	return empty, nil
}

// Stop shutdowns a host.
func (s *HostListener) Stop(ctx context.Context, in *pb.Reference) (empty *googleprotobuf.Empty, err error) {
	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, status.Errorf(codes.FailedPrecondition, scerr.InvalidInstanceError().Error())
	}
	ref := srvutils.GetReference(in)
	if ref == "" {
		return empty, status.Errorf(codes.FailedPrecondition, scerr.InvalidParameterError("ref", "cannot be empty string").Error())
	}

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := srvutils.JobRegister(ctx, cancelFunc, "Stop Host "+ref); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't stop host: no tenant set")
		return empty, status.Errorf(codes.FailedPrecondition, "cannot stop host: no tenant set")
	}

	handler := HostHandler(tenant.Service)
	err = handler.Stop(ctx, ref)
	if err != nil {
		return empty, status.Errorf(codes.Internal, err.Error())
	}

	log.Infof("Host '%s' stopped", ref)
	return empty, nil
}

// Reboot reboots a host.
func (s *HostListener) Reboot(ctx context.Context, in *pb.Reference) (empty *googleprotobuf.Empty, err error) {
	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, status.Errorf(codes.FailedPrecondition, scerr.InvalidInstanceError().Error())
	}
	ref := srvutils.GetReference(in)
	if ref == "" {
		return empty, status.Errorf(codes.FailedPrecondition, scerr.InvalidParameterError("ref", "cannot be empty string").Error())
	}

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)

	if err := srvutils.JobRegister(ctx, cancelFunc, "Reboot Host "+ref); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't reboot host: no tenant set")
		return empty, status.Errorf(codes.FailedPrecondition, "cannot reboot host: no tenant set")
	}

	handler := HostHandler(tenant.Service)
	err = handler.Reboot(ctx, ref)
	if err != nil {
		return empty, status.Errorf(codes.Internal, err.Error())
	}

	log.Infof("Host '%s' successfully rebooted.", ref)
	return empty, nil
}

// List lists hosts managed by SafeScale only, or all hosts.
func (s *HostListener) List(ctx context.Context, in *pb.HostListRequest) (hl *pb.HostList, err error) {
	if s == nil {
		return nil, status.Errorf(codes.FailedPrecondition, scerr.InvalidInstanceError().Error())
	}
	all := in.GetAll()

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("(%v)", all), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)

	ctx, cancelFunc := context.WithCancel(ctx)

	if err := srvutils.JobRegister(ctx, cancelFunc, "List Hosts"); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't list host: no tenant set")
		return nil, status.Errorf(codes.FailedPrecondition, "cannot list hosts: no tenant set")
	}

	handler := HostHandler(tenant.Service)
	hosts, err := handler.List(ctx, all)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
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
		return nil, status.Errorf(codes.FailedPrecondition, scerr.InvalidInstanceError().Error())
	}
	if in == nil {
		return nil, status.Errorf(codes.FailedPrecondition, scerr.InvalidParameterError("in", "cannot be nil").Error())
	}
	name := in.GetName()

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", name), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := srvutils.JobRegister(ctx, cancelFunc, "Create Host "+in.GetName()); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't create host: no tenant set")
		return nil, status.Errorf(codes.FailedPrecondition, "cannot create host: no tenant set")
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

	handler := HostHandler(tenant.Service)
	host, err := handler.Create(ctx,
		name,
		in.GetNetwork(),
		in.GetImageId(),
		in.GetPublic(),
		sizing,
		in.Force,
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	log.Infof("Host '%s' created", name)
	return srvutils.ToPBHost(host), nil

}

// Resize an host
func (s *HostListener) Resize(ctx context.Context, in *pb.HostDefinition) (h *pb.Host, err error) {
	if s == nil {
		return nil, status.Errorf(codes.FailedPrecondition, scerr.InvalidInstanceError().Error())
	}
	if in == nil {
		return nil, status.Errorf(codes.FailedPrecondition, scerr.InvalidParameterError("in", "cannot be nil").Error())
	}
	name := in.GetName()

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", name), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := srvutils.JobRegister(ctx, cancelFunc, "Resize Host "+name); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't resize host: no tenant set")
		return nil, status.Errorf(codes.FailedPrecondition, "cannot resize host: no tenant set")
	}

	handler := HostHandler(tenant.Service)
	host, err := handler.Resize(ctx,
		name,
		int(in.GetCpuCount()),
		in.GetRam(),
		int(in.GetDisk()),
		int(in.GetGpuCount()),
		float32(in.GetCpuFreq()),
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	log.Infof("Host '%s' resized", name)
	return srvutils.ToPBHost(host), nil
}

// Status returns the status of a host (running or stopped mainly)
func (s *HostListener) Status(ctx context.Context, in *pb.Reference) (ht *pb.HostStatus, err error) {
	if s == nil {
		return nil, status.Errorf(codes.FailedPrecondition, scerr.InvalidInstanceError().Error())
	}
	if in == nil {
		return nil, status.Errorf(codes.InvalidArgument, scerr.InvalidParameterError("in", "cannot be nil").Error())
	}
	ref := srvutils.GetReference(in)
	if ref == "" {
		return nil, status.Errorf(codes.FailedPrecondition, "cannot get host status: neither name nor id given as reference")
	}

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := srvutils.JobRegister(ctx, cancelFunc, "Status of Host "+in.GetName()); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't get host status: no tenant set")
		return nil, status.Errorf(codes.FailedPrecondition, "cannot get host status: no tenant set")
	}

	handler := HostHandler(tenant.Service)
	host, err := handler.ForceInspect(ctx, ref)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	return srvutils.ToHostStatus(host), nil
}

// Inspect an host
func (s *HostListener) Inspect(ctx context.Context, in *pb.Reference) (h *pb.Host, err error) {
	if s == nil {
		return nil, status.Errorf(codes.FailedPrecondition, scerr.InvalidInstanceError().Error())
	}
	if in == nil {
		return nil, status.Errorf(codes.InvalidArgument, scerr.InvalidParameterError("in", "cannot be nil").Error())
	}
	ref := srvutils.GetReference(in)
	if ref == "" {
		return nil, status.Errorf(codes.FailedPrecondition, "cannot get host status: neither name nor id given as reference")
	}

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := srvutils.JobRegister(ctx, cancelFunc, "Inspect Host "+in.GetName()); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't inspect host: no tenant set")
		return nil, status.Errorf(codes.FailedPrecondition, "cannot inspect host: no tenant set")
	}

	handler := HostHandler(tenant.Service)
	host, err := handler.ForceInspect(ctx, ref)
	if err != nil {
		return nil, status.Errorf(codes.Internal, fmt.Sprintf("cannot inspect host: %v", err))
	}
	return srvutils.ToPBHost(host), nil
}

// Delete an host
func (s *HostListener) Delete(ctx context.Context, in *pb.Reference) (empty *googleprotobuf.Empty, err error) {
	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, status.Errorf(codes.FailedPrecondition, scerr.InvalidInstanceError().Error())
	}
	if in == nil {
		return empty, status.Errorf(codes.InvalidArgument, scerr.InvalidParameterError("in", "cannot be nil").Error())
	}
	ref := srvutils.GetReference(in)
	if ref == "" {
		return empty, status.Errorf(codes.FailedPrecondition, "cannot get host status: neither name nor id given as reference")
	}

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := srvutils.JobRegister(ctx, cancelFunc, "Delete Host "+in.GetName()); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("Can't delete host: no tenant set")
		return empty, status.Errorf(codes.FailedPrecondition, "cannot delete host: no tenant set")
	}

	handler := HostHandler(tenant.Service)
	err = handler.Delete(ctx, ref)
	if err != nil {
		return empty, status.Errorf(codes.Internal, err.Error())
	}
	log.Infof("Host '%s' successfully deleted.", ref)
	return empty, nil
}

// SSH returns ssh parameters to access an host
func (s *HostListener) SSH(ctx context.Context, in *pb.Reference) (sc *pb.SshConfig, err error) {
	if s == nil {
		return nil, status.Errorf(codes.FailedPrecondition, scerr.InvalidInstanceError().Error())
	}
	if in == nil {
		return nil, status.Errorf(codes.InvalidArgument, scerr.InvalidParameterError("in", "cannot be nil").Error())
	}
	ref := srvutils.GetReference(in)
	if ref == "" {
		return nil, status.Errorf(codes.FailedPrecondition, "cannot get host status: neither name nor id given as reference")
	}

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := srvutils.JobRegister(ctx, cancelFunc, "SSH config of Host "+in.GetName()); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	tenant := GetCurrentTenant()
	if tenant == nil {
		log.Info("cannot delete host: no tenant set")
		return nil, status.Errorf(codes.FailedPrecondition, "cannot ssh host: no tenant set")
	}

	handler := HostHandler(currentTenant.Service)
	sshConfig, err := handler.SSH(ctx, ref)
	if err != nil {
		return nil, err
	}
	return srvutils.ToPBSshConfig(sshConfig), nil
}
