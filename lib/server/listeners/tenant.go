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
	"fmt"

	"github.com/CS-SI/SafeScale/lib/utils/debug"

	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
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
		log.Println("Unique tenant set")
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
func (s *TenantListener) List(ctx context.Context, in *googleprotobuf.Empty) (list *pb.TenantList, err error) {
	if s == nil {
		return nil, status.Errorf(codes.FailedPrecondition, scerr.InvalidInstanceError().Message())
	}

	tracer := debug.NewTracer(nil, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// FIXME: handle error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Tenants List"); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	tenants, err := iaas.GetTenantNames()
	if err != nil {
		return nil, status.Errorf(codes.Internal, getUserMessage(err))
	}

	var tl []*pb.Tenant
	for tenantName, providerName := range tenants {
		tl = append(
			tl, &pb.Tenant{
				Name:     tenantName,
				Provider: providerName,
			},
		)
	}

	return &pb.TenantList{Tenants: tl}, nil
}

// Get returns the name of the current tenant used
func (s *TenantListener) Get(ctx context.Context, in *googleprotobuf.Empty) (tn *pb.TenantName, err error) {
	if s == nil {
		// FIXME: return a status.Errorf
		return nil, status.Errorf(codes.FailedPrecondition, scerr.InvalidInstanceError().Message())
	}

	tracer := debug.NewTracer(nil, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// FIXME: handle error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Tenant Get"); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	getCurrentTenant()
	if currentTenant == nil {
		log.Info("Can't get tenant: no tenant set")
		return nil, status.Errorf(codes.FailedPrecondition, "cannot get tenant: no tenant set")
	}
	return &pb.TenantName{Name: currentTenant.name}, nil
}

// Set the the tenant to use for each command
func (s *TenantListener) Set(ctx context.Context, in *pb.TenantName) (empty *googleprotobuf.Empty, err error) {
	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, status.Errorf(codes.FailedPrecondition, scerr.InvalidInstanceError().Message())
	}
	if in == nil {
		return empty, status.Errorf(codes.InvalidArgument, scerr.InvalidParameterError("in", "cannot be nil").Message())
	}
	name := in.GetName()
	// FIXME: validate parameters

	tracer := debug.NewTracer(nil, fmt.Sprintf("('%s')", name), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// FIXME: handle error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Tenant Set "+name); err == nil {
		defer srvutils.JobDeregister(ctx)
	}

	if currentTenant != nil && currentTenant.name == in.GetName() {
		return empty, nil
	}

	service, err := iaas.UseService(in.GetName())
	if err != nil {
		return empty, fmt.Errorf("unable to set tenant '%s': %s", name, getUserMessage(err))
	}
	currentTenant = &Tenant{name: in.GetName(), Service: service}
	log.Infof("Current tenant is now '%s'", name)
	return empty, nil
}
