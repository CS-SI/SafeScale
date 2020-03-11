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

	"github.com/asaskevich/govalidator"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// Tenant structure to handle name and clientAPI for a tenant
type Tenant struct {
	name    string
	Service iaas.Service
}

var (
	currentTenant *Tenant
)

// GetCurrentTenant contains the current tenant
var GetCurrentTenant = getCurrentTenant

// getCurrentTenant returns the tenant used for commands or, if not set, set the tenant to use if it is the only one registered
func getCurrentTenant() *Tenant {
	if currentTenant == nil {
		tenants, err := iaas.GetTenantNames()
		if err != nil || len(tenants) != 1 {
			return nil
		}
		// Set unique tenant as selected
		logrus.Println("Unique tenant set")
		for name := range tenants {
			service, err := iaas.UseService(name)
			if err != nil {
				return nil
			}
			currentTenant = &Tenant{name: name, Service: service}
		}
	}
	return currentTenant
}

// TenantListener server is used to implement SafeScale.safescale.
type TenantListener struct{}

// List registered tenants
func (s *TenantListener) List(ctx context.Context, in *googleprotobuf.Empty) (_ *protocol.TenantList, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot list tenants").ToGRPCStatus()
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

	// ctx, cancelFunc := context.WithCancel(ctx)
	task, err := concurrency.NewTaskWithContext(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer task.Close()

	tracer := concurrency.NewTracer(task, true, "").WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	tenants, err := iaas.GetTenantNames()
	if err != nil {
		return nil, err
	}

	var list []*protocol.Tenant
	for tenantName, providerName := range tenants {
		list = append(list, &protocol.Tenant{
			Name:     tenantName,
			Provider: providerName,
		})
	}

	return &protocol.TenantList{Tenants: list}, nil
}

// Get returns the name of the current tenant used
func (s *TenantListener) Get(ctx context.Context, in *googleprotobuf.Empty) (_ *protocol.TenantName, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot get tenant").ToGRPCStatus()
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

	// ctx, cancelFunc := context.WithCancel(ctx)
	task, err := concurrency.NewTaskWithContext(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer task.Close()

	tracer := concurrency.NewTracer(nil, true, "").WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	getCurrentTenant()
	if currentTenant == nil {
		return nil, scerr.NotFoundError("no tenant set")
	}
	return &protocol.TenantName{Name: currentTenant.name}, nil
}

// Set the the tenant to use for each command
func (s *TenantListener) Set(ctx context.Context, in *protocol.TenantName) (empty *googleprotobuf.Empty, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot set tenant").ToGRPCStatus()
		}
	}()

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, scerr.InvalidInstanceError()
	}
	if ctx == nil {
		return empty, scerr.InvalidParameterError("ctx", "cannot be nil")
	}
	if in == nil {
		return empty, scerr.InvalidParameterError("in", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	// ctx, cancelFunc := context.WithCancel(ctx)
	task, err := concurrency.NewTaskWithContext(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer task.Close()

	name := in.GetName()

	tracer := concurrency.NewTracer(task, true, "('%s')", name).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	if currentTenant != nil && currentTenant.name == in.GetName() {
		return empty, nil
	}

	service, err := iaas.UseService(in.GetName())
	if err != nil {
		return empty, err
	}
	currentTenant = &Tenant{name: in.GetName(), Service: service}
	return empty, nil
}

// Cleanup removes everything corresponding to SafeScale from tenant (metadata in particular)
func (s *TenantListener) Cleanup(ctx context.Context, in *protocol.TenantCleanupRequest) (empty *googleprotobuf.Empty, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot cleanup tenant").ToGRPCStatus()
		}
	}()

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, scerr.InvalidInstanceError()
	}
	if ctx == nil {
		return empty, scerr.InvalidParameterError("ctx", "cannot be nil")
	}
	if in == nil {
		return empty, scerr.InvalidParameterError("in", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	// ctx, cancelFunc := context.WithCancel(ctx)
	task, err := concurrency.NewTaskWithContext(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer task.Close()

	name := in.GetName()

	tracer := concurrency.NewTracer(task, true, "('%s')", name).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	if currentTenant != nil && currentTenant.name == in.GetName() {
		return empty, nil
	}

	service, err := iaas.UseService(in.GetName())
	if err != nil {
		return empty, err
	}

	err = service.TenantCleanup(in.Force)
	return empty, err
}
