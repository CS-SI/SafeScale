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

	"github.com/CS-SI/SafeScale/iaas"
	pb "github.com/CS-SI/SafeScale/safescale"
	"github.com/CS-SI/SafeScale/safescale/utils"
)

// Tenant structure to handle name and clientAPI for a tenant
type Tenant struct {
	name    string
	Service *iaas.Service
}

var (
	currentTenant *Tenant
)

// TenantListener server is used to implement SafeScale.safescale.
type TenantListener struct{}

// List registerd tenants
func (s *TenantListener) List(ctx context.Context, in *google_protobuf.Empty) (*pb.TenantList, error) {
	log.Infoln("Listeners: receiving \"tenant list\"")
	log.Debugln(">>> TenantListener::List()")
	defer log.Debugln("<<< TenantListener::List()")

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
	log.Infoln("Listeners: receiving \"tenant get\"")
	log.Debugln(">>> TenantListener::Get()")
	defer log.Debugln(">>> TenantListener::Get()")

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

// GetCurrentTenant contains the current tenant
var GetCurrentTenant = getCurrentTenant

// getCurrentTenant returns the tenant used for commands or, if not set, set the tenant to use if it is the only one registerd
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

// Set the the tenant to use for each command
func (s *TenantListener) Set(ctx context.Context, in *pb.TenantName) (*google_protobuf.Empty, error) {
	log.Infof("Listeners: receiving \"tenant set %s\"", in.Name)
	log.Debugf(">>> TenantListener::Set(%s)", in.Name)
	defer log.Debugf("<<< TenantListener::Set(%s)", in.Name)

	ctx, cancelFunc := context.WithCancel(ctx)

	if err := utils.ProcessRegister(ctx, cancelFunc, "Tenant Set "+in.GetName()); err == nil {
		defer utils.ProcessDeregister(ctx)
	}

	if currentTenant != nil && currentTenant.name == in.GetName() {
		return &google_protobuf.Empty{}, nil
	}

	service, err := iaas.UseService(in.GetName())
	if err != nil {
		return &google_protobuf.Empty{}, fmt.Errorf("Unable to set tenant '%s': %s", in.GetName(), err.Error())
	}
	currentTenant = &Tenant{name: in.GetName(), Service: service}
	log.Infof("Current tenant is now '%s'", in.GetName())
	return &google_protobuf.Empty{}, nil
}
