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

	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils"
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
func (s *TenantListener) List(ctx context.Context, in *google_protobuf.Empty) (_ *pb.TenantList, err error) {
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

	tracer := concurrency.NewTracer(nil, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// LATER: handle jobregister error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Tenants List"); err == nil {
		defer srvutils.JobDeregister(ctx)
	} /* else {
		return nil, scerr.InvalidInstanceContentError("ctx", "has no uuid").ToGRPCStatus()
	}*/

	tenants, err := iaas.GetTenantNames()
	if err != nil {
		return nil, scerr.Wrap(err, "cannot list tenants").ToGRPCStatus()
	}

	var list []*pb.Tenant
	for tenantName, providerName := range tenants {
		list = append(list, &pb.Tenant{
			Name:     tenantName,
			Provider: providerName,
		})
	}

	return &pb.TenantList{Tenants: list}, nil
}

// Get returns the name of the current tenant used
func (s *TenantListener) Get(ctx context.Context, in *google_protobuf.Empty) (_ *pb.TenantName, err error) {
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

	tracer := concurrency.NewTracer(nil, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// LATER: handle jobregister error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Tenant Get"); err == nil {
		defer srvutils.JobDeregister(ctx)
	} /* else {
		return nil, scerr.InvalidInstanceContentError("ctx", "has no uuid").ToGRPCStatus()
	}*/

	getCurrentTenant()
	if currentTenant == nil {
		msg := "cannot get tenant: no tenant set"
		tracer.Trace(utils.Capitalize(msg))
		return nil, status.Errorf(codes.FailedPrecondition, msg)
	}
	return &pb.TenantName{Name: currentTenant.name}, nil
}

// Set the the tenant to use for each command
func (s *TenantListener) Set(ctx context.Context, in *pb.TenantName) (empty *google_protobuf.Empty, err error) {
	empty = &google_protobuf.Empty{}
	if s == nil {
		return empty, status.Errorf(codes.FailedPrecondition, scerr.InvalidInstanceError().Error())
	}
	if in == nil {
		return empty, status.Errorf(codes.InvalidArgument, scerr.InvalidParameterError("in", "cannot be nil").Error())
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

	name := in.GetName()

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", name), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// LATER: handle jobregister error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Tenant Set "+name); err == nil {
		defer srvutils.JobDeregister(ctx)
	} /* else {
		return empty, scerr.InvalidInstanceContentError("ctx", "has no uuid").ToGRPCStatus()
	}*/

	if currentTenant != nil && currentTenant.name == in.GetName() {
		return empty, nil
	}

	service, err := iaas.UseService(in.GetName())
	if err != nil {
		return empty, scerr.Wrap(err, "cannot set tenant").ToGRPCStatus()
	}
	currentTenant = &Tenant{name: in.GetName(), Service: service}
	return empty, nil
}

//StorageTenants structure handle tenants names and storages services for a group of storage tenants
type StorageTenants struct {
	names           []string
	StorageServices *iaas.StorageServices
}

var (
	currentStorageTenants *StorageTenants
)

// GetCurrentStorageTenants contains the current tenant
var GetCurrentStorageTenants = getCurrentStorageTenants

// getCurrentTenant returns the tenant used for commands or, if not set, set the tenant to use if it is the only one registered
func getCurrentStorageTenants() *StorageTenants {
	//TODO-AJ should we select all tenants with storage, or still auto selecting tenant only when there is only one available tenant?
	if currentStorageTenants == nil {
		tenants, err := iaas.GetTenantNames()
		if err != nil || len(tenants) != 1 {
			return nil
		}
		// Set unique tenant as selected
		logrus.Println("Unique tenant set")
		for name := range tenants {
			nameSlice := []string{name}
			storageService, err := iaas.UseStorages(nameSlice)
			if err != nil {
				return nil
			}
			currentStorageTenants = &StorageTenants{names: nameSlice, StorageServices: storageService}
		}
	}
	return currentStorageTenants
}

// StorageList lists registered storage tenants
func (s *TenantListener) StorageList(ctx context.Context, in *google_protobuf.Empty) (_ *pb.TenantList, err error) {
	if s == nil {
		return nil, status.Errorf(codes.FailedPrecondition, scerr.InvalidInstanceError().Error())
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

	tracer := concurrency.NewTracer(nil, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// LATER: handle jobregister error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Tenant StorageList"); err == nil {
		defer srvutils.JobDeregister(ctx)
	} /* else {
		return nil, scerr.InvalidInstanceContentError("ctx", "has no uuid").ToGRPCStatus()
	}*/

	tenants, err := iaas.GetTenants()
	if err != nil {
		return nil, scerr.Wrap(err, "cannot list storage tenants").ToGRPCStatus()
	}

	var tenantList []*pb.Tenant
	for _, tenant := range tenants {
		tenantCast, ok := tenant.(map[string]interface{})
		if ok {
			if _, ok := tenantCast["objectstorage"]; ok {
				tenantList = append(tenantList, &pb.Tenant{
					Name:     tenantCast["name"].(string),
					Provider: tenantCast["client"].(string),
				})
			}
		}
	}

	return &pb.TenantList{Tenants: tenantList}, nil
}

// StorageGet returns the name of the current storage tenants used for data related commands
func (s *TenantListener) StorageGet(ctx context.Context, in *google_protobuf.Empty) (_ *pb.TenantNameList, err error) {
	if s == nil {
		return nil, status.Errorf(codes.InvalidArgument, scerr.InvalidInstanceError().Error())
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

	tracer := concurrency.NewTracer(nil, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// LATER: handle jobregister error
	if err := srvutils.JobRegister(ctx, cancelFunc, "Tenant StorageGet"); err == nil {
		defer srvutils.JobDeregister(ctx)
	} /* else {
		return nil, scerr.InvalidInstanceContentError("ctx", "has no uuid").ToGRPCStatus()
	}*/

	getCurrentStorageTenants()
	if currentStorageTenants == nil {
		msg := "cannot get storage tenants: no tenant set"
		tracer.Trace(utils.Capitalize(msg))
		return nil, status.Errorf(codes.FailedPrecondition, msg)
	}

	return &pb.TenantNameList{Names: currentStorageTenants.names}, nil
}

// StorageSet set the tenants to use for data related commands
func (s *TenantListener) StorageSet(ctx context.Context, in *pb.TenantNameList) (empty *google_protobuf.Empty, err error) {
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

	tracer := concurrency.NewTracer(nil, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	ctx, cancelFunc := context.WithCancel(ctx)
	// LATER: handle jobregister error
	if err := srvutils.JobRegister(ctx, cancelFunc, fmt.Sprintf("Tenant StorageSet %v", in.GetNames())); err == nil {
		defer srvutils.JobDeregister(ctx)
	} /* else {
		return empty, scerr.InvalidInstanceContentError("ctx", "has no uuid").ToGRPCStatus()
	}*/

	storageServices, err := iaas.UseStorages(in.GetNames())
	if err != nil {
		return empty, scerr.Wrap(err, "cannot set storage tenants").ToGRPCStatus()
	}

	currentStorageTenants = &StorageTenants{names: in.GetNames(), StorageServices: storageServices}
	tracer.Trace("Current storage tenants are now '%v'", in.GetNames())
	return empty, nil
}
