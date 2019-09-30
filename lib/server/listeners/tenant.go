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

	log "github.com/sirupsen/logrus"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/utils"
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
func (s *TenantListener) List(ctx context.Context, in *google_protobuf.Empty) (*pb.TenantList, error) {
	// defer timing.TimerWithLevel(fmt.Sprintf("TenantListener::List() called"), log.TraceLevel)()

	ctx, cancelFunc := context.WithCancel(ctx)

	if err := utils.ProcessRegister(ctx, cancelFunc, "Tenants List"); err == nil {
		defer utils.ProcessDeregister(ctx)
	}

	tenants, err := iaas.GetTenantNames()
	if err != nil {
		return nil, err
	}

	var tl []*pb.Tenant
	for tenantName, providerName := range tenants {
		tl = append(tl, &pb.Tenant{
			Name:     tenantName,
			Provider: providerName,
		})
	}

	return &pb.TenantList{Tenants: tl}, nil
}

// Get returns the name of the current tenant used
func (s *TenantListener) Get(ctx context.Context, in *google_protobuf.Empty) (*pb.TenantName, error) {
	// defer timing.TimerWithLevel(fmt.Sprintf("TenantListener::Get() called"), log.TraceLevel)()

	ctx, cancelFunc := context.WithCancel(ctx)

	if err := utils.ProcessRegister(ctx, cancelFunc, "Tenant Get"); err == nil {
		defer utils.ProcessDeregister(ctx)
	}

	getCurrentTenant()
	if currentTenant == nil {
		log.Info("Can't get tenant: no tenant set")
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't get tenant: no tenant set")
	}
	return &pb.TenantName{Name: currentTenant.name}, nil
}

// Set the the tenant to use for each command
func (s *TenantListener) Set(ctx context.Context, in *pb.TenantName) (*google_protobuf.Empty, error) {
	// defer timing.TimerWithLevel(fmt.Sprintf("TenantListener::Set(%s) called", in.Name), log.TraceLevel)()

	ctx, cancelFunc := context.WithCancel(ctx)

	if err := utils.ProcessRegister(ctx, cancelFunc, "Tenant Set "+in.GetName()); err == nil {
		defer utils.ProcessDeregister(ctx)
	}

	if currentTenant != nil && currentTenant.name == in.GetName() {
		return &google_protobuf.Empty{}, nil
	}

	service, err := iaas.UseService(in.GetName())
	if err != nil {
		return &google_protobuf.Empty{}, fmt.Errorf("unable to set tenant '%s': %s", in.GetName(), err.Error())
	}
	currentTenant = &Tenant{name: in.GetName(), Service: service}
	log.Infof("Current tenant is now '%s'", in.GetName())
	return &google_protobuf.Empty{}, nil
}

//StorageTenants strcture handle tenants names and storages services for a group of storage tenants
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
		log.Println("Unique tenant set")
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
func (s *TenantListener) StorageList(ctx context.Context, in *google_protobuf.Empty) (*pb.TenantList, error) {
	// defer timing.TimerWithLevel(fmt.Sprintf("TenantListener::StorageList() called"), log.TraceLevel)()

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := utils.ProcessRegister(ctx, cancelFunc, "Tenant StorageList"); err == nil {
		defer utils.ProcessDeregister(ctx)
	}

	tenants, err := iaas.GetTenants()
	if err != nil {
		return nil, err
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
func (s *TenantListener) StorageGet(ctx context.Context, in *google_protobuf.Empty) (*pb.TenantNameList, error) {
	// defer timing.TimerWithLevel(fmt.Sprintf("TenantListener::StorageGet() called"), log.TraceLevel)()

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := utils.ProcessRegister(ctx, cancelFunc, "Tenant StorageGet"); err == nil {
		defer utils.ProcessDeregister(ctx)
	}

	getCurrentStorageTenants()
	if currentStorageTenants == nil {
		log.Info("Can't get storage tenants: no tenant set")
		return nil, grpc.Errorf(codes.FailedPrecondition, "can't get storage tenants: no tenant set")
	}

	return &pb.TenantNameList{Names: currentStorageTenants.names}, nil
}

// StorageSet set the tenants to use for data related commands
func (s *TenantListener) StorageSet(ctx context.Context, in *pb.TenantNameList) (*google_protobuf.Empty, error) {
	// defer timing.TimerWithLevel(fmt.Sprintf("TenantListener::StorageSet(%v) called", in.Names), log.TraceLevel)()

	ctx, cancelFunc := context.WithCancel(ctx)
	if err := utils.ProcessRegister(ctx, cancelFunc, fmt.Sprintf("Tenant StorageSet %v", in.GetNames())); err == nil {
		defer utils.ProcessDeregister(ctx)
	}

	storageServices, err := iaas.UseStorages(in.GetNames())
	if err != nil {
		return &google_protobuf.Empty{}, fmt.Errorf("unable to set tenants '%v': %s", in.GetNames(), err.Error())
	}

	currentStorageTenants = &StorageTenants{names: in.GetNames(), StorageServices: storageServices}
	log.Infof("Current storage tenants are now '%v'", in.GetNames())
	return &google_protobuf.Empty{}, nil
}
