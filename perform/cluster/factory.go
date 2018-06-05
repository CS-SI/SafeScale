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

package cluster

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"log"
	"strings"

	pb "github.com/CS-SI/SafeScale/broker"

	"github.com/CS-SI/SafeScale/utils"

	clusterapi "github.com/CS-SI/SafeScale/perform/cluster/api"
	"github.com/CS-SI/SafeScale/perform/cluster/api/Flavor"
	"github.com/CS-SI/SafeScale/perform/cluster/metadata"

	"github.com/CS-SI/SafeScale/perform/cluster/dcos"
)

//Get returns the ClusterAPI instance corresponding to the cluster named 'name'
func Get(name string) (clusterapi.ClusterAPI, error) {
	var data metadata.Record
	found, err := data.Read(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get information about Cluster '%s': %s", name, err.Error())
	}
	if !found {
		return nil, nil
	}

	var instance clusterapi.ClusterAPI
	switch data.Common.Flavor {
	case Flavor.DCOS:
		instance, err = dcos.Load(data)
		if err != nil {
			return nil, err
		}
	}
	if instance == nil {
		return nil, nil
	}

	_, err = instance.GetState()
	if err != nil {
		return nil, fmt.Errorf("failed to get state of the cluster: %s", err.Error())
	}
	return instance, nil
}

//Create creates a cluster following the parameters of the request
func Create(req clusterapi.Request) (clusterapi.ClusterAPI, error) {
	// Validates parameters
	if req.Name == "" {
		return nil, fmt.Errorf("Invalid parameter req.Name: can't be empty")
	}
	if req.CIDR == "" {
		return nil, fmt.Errorf("Invalid parameter req.CIDR: can't be empty")
	}

	var network *pb.Network
	var instance clusterapi.ClusterAPI

	log.Printf("Creating infrastructure for cluster '%s'", req.Name)

	tenant, err := utils.GetCurrentTenant()
	if err != nil {
		return nil, err
	}

	// Creates network
	log.Printf("Creating Network 'net-%s'", req.Name)
	req.Name = strings.ToLower(req.Name)
	network, err = utils.CreateNetwork("net-"+req.Name, req.CIDR)
	if err != nil {
		err = fmt.Errorf("Failed to create Network '%s': %s", req.Name, err.Error())
		return nil, err
	}

	switch req.Flavor {
	case Flavor.DCOS:
		req.NetworkID = network.ID
		req.Tenant = tenant
		instance, err = dcos.Create(req)
		if err != nil {
			//utils.DeleteNetwork(network.ID)
			return nil, err
		}
	}

	log.Printf("Cluster '%s' created and initialized successfully", req.Name)
	return instance, nil
}

// Delete deletes the infrastructure of the cluster named 'name'
func Delete(name string) error {
	instance, err := Get(name)
	if err != nil {
		return fmt.Errorf("failed to find a cluster named '%s': %s", name, err.Error())
	}
	if instance == nil {
		return fmt.Errorf("Cluster '%s' not found", name)
	}

	networkID := instance.GetNetworkID()

	// Deletes all the infrastructure built for the cluster
	err = instance.Delete()
	if err != nil {
		return fmt.Errorf("failed to delete infrastructure of cluster '%s': %s", name, err.Error())
	}

	// Deletes the network and related stuff
	utils.DeleteNetwork(networkID)

	// Cleanup Object Storage metadata
	return metadata.Delete(name)
}

//List lists the clusters already created
func List() ([]clusterapi.Cluster, error) {
	var clusterList []clusterapi.Cluster
	err := utils.BrowseMetadata(metadata.Path, func(buf *bytes.Buffer) error {
		var data metadata.Record
		err := gob.NewDecoder(buf).Decode(&data)
		if err != nil {
			return err
		}
		clusterList = append(clusterList, data.Common)
		return nil
	})
	return clusterList, err
}
