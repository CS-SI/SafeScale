package main

import (
	"fmt"
	"log"
	"runtime"

	"github.com/SafeScale/perform/cluster"
	clusterapi "github.com/SafeScale/perform/cluster/api"
	"github.com/SafeScale/perform/cluster/api/Complexity"
	"github.com/SafeScale/perform/cluster/api/Flavor"
	"github.com/SafeScale/perform/cluster/api/NodeType"

	providerapi "github.com/SafeScale/providers/api"
)

//Run runs the deployment
func Run() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	cf := cluster.NewFactory()
	tenant := "TestFlexibleEngine"
	cm, err := cf.GetManager(tenant)
	if err != nil {
		fmt.Printf("Failed to instanciate Cluster Manager for tenant '%s'.\n", tenant)
		return
	}

	clusterName := "test-cluster"
	cluster, err := cm.GetCluster(clusterName)
	if err != nil {
		fmt.Printf("Failed to load cluster '%s' parameters: %s\n", clusterName, err.Error())
		return
	}
	if cluster == nil {
		log.Printf("Cluster '%s' not found, creating it (this will take a while)\n", clusterName)
		cluster, err = cm.CreateCluster(clusterapi.ClusterRequest{
			Name:       clusterName,
			Complexity: Complexity.Dev,
			//Complexity: Complexity.Normal,
			//Complexity: Complexity.Volume,
			CIDR:   "192.168.0.0/28",
			Flavor: Flavor.DCOS,
		})
		if err != nil {
			fmt.Printf("Failed to create cluster: %s\n", err.Error())
			return
		}
	} else {
		fmt.Printf("Cluster '%s' already created.\n", clusterName)
	}

	state, err := cluster.GetState()
	if err != nil {
		fmt.Println("Failed to get cluster state.")
		return
	}
	fmt.Printf("Cluster state: %s\n", state.String())

	// Figures out the best template for Agent nodes
	service := cm.GetService()
	tmplAgentNode, err := service.SelectTemplatesBySize(providerapi.SizingRequirements{
		MinCores:    2,
		MinRAMSize:  8,
		MinDiskSize: 60,
	})
	if err != nil {
		fmt.Printf("Failed to find a template suitable for Agent Nodes: %s\n", err.Error())
		return
	}

	// Creates a Private Agent Node
	_, err = cluster.AddNode(NodeType.PrivateAgent, providerapi.VMRequest{
		TemplateID: tmplAgentNode[0].ID,
	})
	if err != nil {
		fmt.Printf("Failed to create Private Agent Node: %s\n", err.Error())
		return
	}
}

func main() {
	Run()
}
