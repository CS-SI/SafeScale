package commands

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
	for name := range providers.Services() {
		tl = append(tl, &pb.Tenant{
			Name:     name,
			Provider: "myprovider",
		})
	}

	return &pb.TenantList{Tenants: tl}, nil
}

//Reload reloads tenants from configuration file
func (s *TenantServiceServer) Reload(ctx context.Context, in *google_protobuf.Empty) (*google_protobuf.Empty, error) {
	// TODO To be implemented
	log.Println("Reload called")
	return &google_protobuf.Empty{}, nil
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
		if len(providers.Services()) != 1 {
			return nil
		}
		// Set unqiue tenant as selected
		log.Println("Unique tenant set")
		for name, service := range providers.Services() {
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
		return nil, fmt.Errorf("Unknown tenant '%s'", in.GetName())
	}
	currentTenant = &Tenant{name: in.GetName(), client: clientAPI}
	log.Printf("Current tenant is now '%s'", in.GetName())
	return &google_protobuf.Empty{}, nil
}
