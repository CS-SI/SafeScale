package dcos

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/SafeScale/providers"
	providerapi "github.com/SafeScale/providers/api"

	clusterapi "github.com/SafeScale/cluster/api"
	"github.com/SafeScale/cluster/api/ClusterState"
	"github.com/SafeScale/cluster/api/Complexity"
	"github.com/SafeScale/cluster/api/NodeType"
)

//Manager is the implementation for DCOS
type Manager struct {
	clusterapi.ClusterManager
}

//GetService returns the service corresponding to the tenant associated with the ClusterManager
func (m *Manager) GetService() *providers.Service {
	return m.ClusterManager.Service
}

//GetTenantName returns the tenant name associated with the ClusterManager
func (m *Manager) GetTenantName() string {
	return m.ClusterManager.Tenant
}

//CreateCluster creates a cluster following the parameters of the request
func (m *Manager) CreateCluster(req clusterapi.ClusterRequest) (clusterapi.ClusterAPI, error) {
	// Validates parameters
	if req.Name == "" {
		return nil, fmt.Errorf("Invalid parameter req.Name: can't be empty")
	}
	if req.CIDR == "" {
		return nil, fmt.Errorf("Invalid parameter req.CIDR: can't be empty")
	}

	req.Name = strings.ToLower(req.Name)
	log.Printf("Creating cluster '%s'", req.Name)

	svc := m.GetService()

	// Figures out the best image for the job (DCOS supports only REHL 7, CentOS 7 and CoreOS)
	image, err := svc.SearchImage("CentOS 7.3")
	if err != nil {
		return nil, fmt.Errorf("Failed to find image for CentOS 7.3")
	}

	// Figures out the best template for Bootstrap node
	tmplBootstrap, err := svc.SelectTemplatesBySize(providerapi.SizingRequirements{
		MinCores:    2,
		MinRAMSize:  16,
		MinDiskSize: 60,
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to find a template suitable for bootstrap server: %s", err.Error())
	}

	// Figures out the best template for Master node(s)
	tmplMaster, err := svc.SelectTemplatesBySize(providerapi.SizingRequirements{
		MinCores:    4,
		MinRAMSize:  32,
		MinDiskSize: 120,
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to find a template suitable for master server: %s", err.Error())
	}

	// Create a KeyPair for the cluster
	name := "cluster_" + req.Name + "_key"
	svc.DeleteKeyPair(name)
	kp, err := svc.CreateKeyPair(name)
	if err != nil {
		return nil, fmt.Errorf("failed to create Key Pair: %s", err.Error())
	}

	var masterCount int
	var network *providerapi.Network
	var gwRequest providerapi.GWRequest
	var img *providerapi.Image
	var keypair *providerapi.KeyPair
	var tpls []providerapi.VMTemplate

	// Saving cluster parameters, with status 'Creating'
	cluster := &Cluster{
		definition: &ClusterDefinition{
			Common: clusterapi.Cluster{
				Name:       req.Name,
				State:      ClusterState.Creating,
				Complexity: req.Complexity,
				Keypair:    kp,
			},
		},
		Manager: m,
	}

	// Creates network
	log.Printf("Creating Network 'net-%s'", req.Name)
	network, err = svc.CreateNetwork(providerapi.NetworkRequest{
		Name: "net-" + req.Name,
		CIDR: req.CIDR,
	})
	if err != nil {
		err = fmt.Errorf("Failed to create Network '%s': %s", req.Name, err.Error())
		goto cleanKeypair
	}
	cluster.definition.NetworkID = network.ID
	//sleep 3s to wait Network in READY state for now, has to be smarter... Probably in service.CreateNetwork()
	fmt.Println("Sleeping 3s...")
	time.Sleep(3 * time.Second)
	fmt.Println("Waking up...")

	// Creates a Gateway (when calling broker API, won't be necessary)
	log.Printf("Creating gateway of network '%s'", network.Name)
	tpls, err = svc.SelectTemplatesBySize(providerapi.SizingRequirements{
		MinCores:    1,
		MinRAMSize:  1,
		MinDiskSize: 20,
	})
	img, err = svc.SearchImage("Ubuntu 16.04")
	if err != nil {
		goto cleanNetwork
	}
	keypair, err = svc.CreateKeyPair("kp_" + network.Name)
	if err != nil {
		goto cleanNetwork
	}
	defer svc.DeleteKeyPair(keypair.ID)
	gwRequest = providerapi.GWRequest{
		ImageID:    img.ID,
		NetworkID:  network.ID,
		KeyPair:    keypair,
		TemplateID: tpls[0].ID,
	}
	err = svc.CreateGateway(gwRequest)
	if err != nil {
		goto cleanNetwork
	}

	// Creates bootstrap/upgrade server
	log.Printf("Creating DCOS Bootstrap server")
	_, err = cluster.AddNode(NodeType.Bootstrap, providerapi.VMRequest{
		TemplateID: tmplBootstrap[0].ID,
		ImageID:    image.ID,
	})
	if err != nil {
		err = fmt.Errorf("failed to create DCOS bootstrap server: %s", err.Error())
		goto cleanGateway
	}

	err = cluster.SaveDefinition()
	if err != nil {
		err = fmt.Errorf("failed to create cluster '%s': %s", req.Name, err.Error())
		goto cleanBootstrap
	}

	switch req.Complexity {
	case Complexity.Dev:
		masterCount = 1
	case Complexity.HighAvailability:
		masterCount = 3
	case Complexity.HighVolume:
		masterCount = 5
	}

	log.Printf("Creating DCOS Master servers (%d)", masterCount)
	for i := 1; i <= masterCount; i++ {
		// Creates Master Node
		_, err = cluster.AddNode(NodeType.Master, providerapi.VMRequest{
			TemplateID: tmplMaster[0].ID,
			ImageID:    image.ID,
		})
		if err != nil {
			err = fmt.Errorf("failed to add DCOS master node %d: %s", i, err.Error())
			goto cleanMasters
		}
	}

	log.Printf("Configuring cluster")
	err = cluster.configure()
	if err != nil {
		err = fmt.Errorf("failed to configure bootstrap and masters servers: %s", err.Error())
		goto cleanMasters
	}

	// Cluster created and configured successfully, saving again to Object Storage
	cluster.definition.Common.State = ClusterState.Created
	err = cluster.SaveDefinition()
	if err != nil {
		goto cleanMasters
	}

	log.Printf("Cluster '%s' created and initialized successfully", req.Name)
	return cluster, nil

cleanMasters:
	//	for _, id := range cluster.definition.MasterIDs {
	//		svc.DeleteVM(id)
	//	}
cleanBootstrap:
	//	svc.DeleteVM(cluster.definition.BootstrapID)
cleanGateway:
	//  svc.DeleteGateway(cluster.definition.NetworkID)
cleanNetwork:
	//	svc.DeleteNetwork(cluster.definition.NetworkID)
cleanKeypair:
	//	svc.DeleteKeyPair(kp.ID)
	cluster.RemoveDefinition()
	return nil, err
}

// DeleteCluster deletes the infrastructure of the cluster named 'name'
func (m *Manager) DeleteCluster(name string) error {
	clusterAPI, err := m.GetCluster(name)
	if err != nil {
		return fmt.Errorf("failed to find a cluster named '%s': %s", name, err.Error())
	}
	cluster, ok := clusterAPI.(*Cluster)
	if !ok {
		return fmt.Errorf("Cluster struct found doesn't correspond to instance of dcos.Cluster")
	}

	// Cleanup Object Storage data
	return cluster.RemoveDefinition()
}

//GetCluster returns the Cluster object corresponding to the cluster named 'name'
func (m *Manager) GetCluster(name string) (clusterapi.ClusterAPI, error) {
	cluster := &Cluster{
		definition: &ClusterDefinition{
			Common: clusterapi.Cluster{
				Name: name,
			},
		},
		Manager: m,
	}
	found, err := cluster.ReadDefinition()
	if err != nil {
		return nil, fmt.Errorf("failed to get Cluster '%s': %s", name, err.Error())
	}
	if found {
		_, err = cluster.GetState()
		if err != nil {
			return nil, fmt.Errorf("failed to get state of the cluster: %s", err.Error())
		}
		return cluster, nil
	}
	return nil, nil
}

//ListClusters lists the clusters already created
func (m *Manager) ListClusters() (*[]string, error) {
	return nil, nil
}

//StartCluster starts the cluster named 'name'
func (m *Manager) StartCluster(name string) error {
	cluster, err := m.GetCluster(name)
	if err != nil {
		return fmt.Errorf("Failed to find cluster named '%s': %s", name, err.Error())
	}
	return cluster.Start()
}

//StopCluster stops the cluster named 'name'.
func (m *Manager) StopCluster(name string) error {
	cluster, err := m.GetCluster(name)
	if err != nil {
		return fmt.Errorf("Failed to find cluster named '%s': %s", name, err.Error())
	}
	return cluster.Stop()
}

//GetState returns the state of the cluster named 'name'
func (m *Manager) GetState(name string) (ClusterState.Enum, error) {
	cluster, err := m.GetCluster(name)
	if err != nil {
		return ClusterState.Error, fmt.Errorf("Failed to find cluster named '%s': %s", name, err.Error())
	}
	return cluster.GetState()
}
