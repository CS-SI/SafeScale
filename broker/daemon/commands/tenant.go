package commands
/*
* Copyright 2015-2018, CS Systemes d'Information, http://www.c-s.fr
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

import (
	"context"
	"fmt"
	"log"

	pb "github.com/SafeScale/broker"
	"github.com/SafeScale/providers"
	"github.com/SafeScale/providers/api"
	_ "github.com/SafeScale/providers/cloudwatt"      // Imported to initialise tenants
	_ "github.com/SafeScale/providers/flexibleengine" // Imported to initialise tenants
	_ "github.com/SafeScale/providers/ovh"            // Imported to initialise tenants
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
)

//Tenant structure to handle name and clientAPI for a tenant
type Tenant struct {
	name   string
	client api.ClientAPI
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

//TenantServiceServer server is used to implement SafeScale.broker.
type TenantServiceServer struct{}

//List registerd tenants
func (s *TenantServiceServer) List(ctx context.Context, in *google_protobuf.Empty) (*pb.TenantList, error) {
	log.Println("List tenant called")

	var tl []*pb.Tenant
	for tenantName, providerName := range providers.Tenants() {
		tl = append(tl, &pb.Tenant{
			Name:     tenantName,
			Provider: providerName,
		})
	}

	return &pb.TenantList{Tenants: tl}, nil
}

//Get returns the name of the current tenant used
func (s *TenantServiceServer) Get(ctx context.Context, in *google_protobuf.Empty) (*pb.TenantName, error) {
	log.Println("Tenant Get called")
	tenant := GetCurrentTenant()
	if tenant == nil {
		return nil, fmt.Errorf("No tenant set")
	}
	return &pb.TenantName{Name: tenant.name}, nil
}

//GetCurrentTenant returns the tenant used for commands or, if not set, set the tenant to use if it is the only one registerd
func GetCurrentTenant() *Tenant {
	if currentTenant == nil {
		if len(providers.Tenants()) != 1 {
			return nil
		}
		// Set unqiue tenant as selected
		log.Println("Unique tenant set")
		for name := range providers.Tenants() {
			service, err := providers.GetService(name)
			if err != nil {
				return nil
			}
			currentTenant = &Tenant{name: name, client: service}
		}
	}
	return currentTenant
}

//Set the the tenant tu use for each command
func (s *TenantServiceServer) Set(ctx context.Context, in *pb.TenantName) (*google_protobuf.Empty, error) {
	log.Println("Tenant Set called")

	if currentTenant != nil && currentTenant.name == in.GetName() {
		log.Printf("Tenant '%s' is already selected", in.GetName())
		return &google_protobuf.Empty{}, nil
	}

	clientAPI, err := providers.GetService(in.GetName())
	if err != nil {
		return nil, fmt.Errorf("Unable to set tenant '%s': %s", in.GetName(), err.Error())
	}
	currentTenant = &Tenant{name: in.GetName(), client: clientAPI}
	log.Printf("Current tenant is now '%s'", in.GetName())
	return &google_protobuf.Empty{}, nil
}
