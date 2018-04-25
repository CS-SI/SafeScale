package main

import (
	"fmt"
	"runtime"

	"github.com/SafeScale/cluster"
	clusterapi "github.com/SafeScale/cluster/api"
	"github.com/SafeScale/cluster/api/Complexity"
	"github.com/SafeScale/cluster/api/Flavor"

	"github.com/SafeScale/providers"
	"github.com/SafeScale/providers/flexibleengine"
)

//Run runs the deployment
func Run() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	sf := providers.NewFactory()
	sf.RegisterClient("flexibleengine", &flexibleengine.Client{})
	err := sf.Load()
	if err != nil {
		fmt.Printf("Error during Service Factory Load: %s", err.Error())
		return
	}
	serviceName := "TestFlexibleEngine"
	service := sf.Services[serviceName]
	if service == nil {
		fmt.Printf("Failed to load service '%s'.\n", serviceName)
		return
	}

	cf := cluster.NewFactory()
	cm, err := cf.GetManager(Flavor.DCOS, "TextFlexibleEngine", service)
	if err != nil {
		fmt.Println("Failed to instanciate Cluster Manager.")
		return
	}

	cluster, err := cm.GetCluster("Test")
	if err != nil {
		fmt.Println("Failed to load cluster 'Test' parameters: %s", err.Error())
		return
	}
	if cluster == nil {
		fmt.Println("Cluster 'Test' not found, creating it")
		cluster, err = cm.CreateCluster(clusterapi.ClusterRequest{
			Name:       "Test",
			Complexity: Complexity.Simple,
			CIDR:       "192.168.0.0/18",
		})
		if err != nil {
			fmt.Printf("Failed to create cluster: %s\n", err.Error())
			return
		}
	} else {
		fmt.Println("Cluster 'Test' already created.")
	}

	state, err := cluster.GetState()
	if err != nil {
		fmt.Println("Failed to get cluster state.")
		return
	}
	fmt.Printf("Cluster state: %d\n", state)
}

func main() {
	Run()
}
