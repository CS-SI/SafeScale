/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

package commands

import (
	"context"
	"fmt"
	pb "github.com/CS-SI/SafeScale/broker"
	_ "github.com/CS-SI/SafeScale/broker/utils" // Imported to initialise tenants
	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	log "github.com/sirupsen/logrus"
)

// Tenant structure to handle name and clientAPI for a tenant
type Tenant struct {
	name   string
	Client api.ClientAPI
}

var (
	currentTenant *Tenant
	// serviceFactory *providers.ServiceFactory
)

// //InitServiceFactory initialise the service factory
// func InitServiceFactory() {
// 	// serviceFactory = providers.NewFactory()
// 	// serviceFactory.RegisterClient("ovh", &ovh.Client{})
// 	// serviceFactory.Load()

// }

// TenantServiceServer server is used to implement SafeScale.broker.
type TenantServiceServer struct{}

// List registerd tenants
func (s *TenantServiceServer) List(ctx context.Context, in *google_protobuf.Empty) (*pb.TenantList, error) {
	log.Println("List tenant called")

	tenants, err := providers.Tenants()
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
func (s *TenantServiceServer) Get(ctx context.Context, in *google_protobuf.Empty) (*pb.TenantName, error) {
	log.Println("Tenant Get called")
	tenant := GetCurrentTenant()
	if tenant == nil {
		return nil, fmt.Errorf("Cannot get tenant : No tenant set")
	}
	return &pb.TenantName{Name: tenant.name}, nil
}

// GetCurrentTenant contains the current tenant
var GetCurrentTenant = getCurrentTenant

// getCurrentTenant returns the tenant used for commands or, if not set, set the tenant to use if it is the only one registerd
func getCurrentTenant() *Tenant {
	if currentTenant == nil {
		tenants, err := providers.Tenants()
		if err != nil || len(tenants) != 1 {
			return nil
		}
		// Set unqiue tenant as selected
		log.Println("Unique tenant set")
		for name := range tenants {
			service, err := providers.GetService(name)
			if err != nil {
				return nil
			}
			currentTenant = &Tenant{name: name, Client: service}
		}
	}
	return currentTenant
}

// Set the the tenant tu use for each command
func (s *TenantServiceServer) Set(ctx context.Context, in *pb.TenantName) (*google_protobuf.Empty, error) {
	log.Printf("Tenant Set called '%s'", in.Name)

	if currentTenant != nil && currentTenant.name == in.GetName() {
		log.Printf("Tenant '%s' is already selected", in.GetName())
		return &google_protobuf.Empty{}, nil
	}

	clientAPI, err := providers.GetService(in.GetName())
	if err != nil {
		return nil, fmt.Errorf("Unable to set tenant '%s': %s", in.GetName(), err.Error())
	}
	currentTenant = &Tenant{name: in.GetName(), Client: clientAPI}
	log.Printf("Current tenant is now '%s'", in.GetName())
	return &google_protobuf.Empty{}, nil
}
