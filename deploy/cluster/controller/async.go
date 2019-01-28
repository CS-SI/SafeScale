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

package controller

import (
	"fmt"
	"strings"
	"time"

	pb "github.com/CS-SI/SafeScale/broker"
	brokerclient "github.com/CS-SI/SafeScale/broker/client"
	"github.com/CS-SI/SafeScale/deploy/cluster/api"
	clusterpropsv1 "github.com/CS-SI/SafeScale/deploy/cluster/controller/properties/v1"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Extension"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/NodeType"
	"github.com/CS-SI/SafeScale/deploy/install"
	"github.com/CS-SI/SafeScale/utils"
	log "github.com/sirupsen/logrus"
)

var (
	timeoutCtxHost = 10 * time.Minute
)

// asyncInstallGateway installs necessary components on the gateway
// Designed to work in goroutine
func asyncInstallGateway(c api.Cluster, b *Blueprint, gw *pb.Host, done chan error) {
	log.Printf("[gateway] starting installation...")

	sshCfg, err := brokerclient.New().Host.SSHConfig(gw.ID)
	if err != nil {
		done <- err
		return
	}
	err = sshCfg.WaitServerReady(5 * time.Minute)
	if err != nil {
		done <- err
		return
	}

	box, err := b.GetTemplateBox()
	if err != nil {
		done <- err
		return
	}
	globalSystemRequirements, err := b.GetGlobalSystemRequirements(c)
	if err != nil {
		done <- err
		return
	}
	data := map[string]interface{}{
		"GlobalSystemRequirements": *globalSystemRequirements,
	}
	retcode, _, _, err := b.ExecuteScript(box, funcMap, "swarm_install_gateway.sh", data, gw.ID)
	if err != nil {
		log.Printf("[gateway] installation failed: %s", err.Error())
		done <- err
		return
	}
	if retcode != 0 {
		log.Printf("[gateway] installation failed: retcode=%d", retcode)
		done <- fmt.Errorf("scripted gateway installation failed with error code %d", retcode)
		return
	}

	// Installs reverseproxy
	doInstall := false
	err = c.GetExtensions().LockForRead(Extension.FeaturesV1).ThenUse(func(v interface{}) error {
		_, doInstall = v.(*clusterpropsv1.Features).Disabled["reverseproxy"]
		return nil
	})
	if err != nil {
		log.Printf("[gateway] installation failed: %s", err.Error())
		done <- err
		return
	}
	if doInstall {
		log.Println("Adding feature 'reverseproxy' on gateway...")
		feature, err := install.NewFeature("reverseproxy")
		if err != nil {
			msg := fmt.Sprintf("failed to prepare feature '%s' for '%s': %s", feature.DisplayName(), gw.Name, err.Error())
			log.Println(msg)
			done <- fmt.Errorf(msg)
			return
		}
		target := install.NewHostTarget(gw)
		results, err := feature.Add(target, install.Variables{}, install.Settings{})
		if err != nil {
			msg := fmt.Sprintf("failed to install feature '%s' on '%s': %s", feature.DisplayName(), gw.Name, err.Error())
			log.Println(msg)
			done <- fmt.Errorf(msg)
			return
		}
		if !results.Successful() {
			msg := fmt.Sprintf("failed to install feature '%s' on '%s': %s", feature.DisplayName(), gw.Name, results.AllErrorMessages())
			log.Println(msg)
			done <- fmt.Errorf(msg)
			return
		}
		log.Println("Feature 'reverseproxy' successfully added on gateway")
	}

	log.Printf("[gateway] preparation successful")
	done <- nil
}

// asyncConfigureGateway prepares the gateway
// Designed to work in goroutine
func asyncConfigureGateway(c api.Cluster, b *Blueprint, gw *pb.Host, done chan error) {
	log.Printf("[gateway] starting configuration...")

	var dnsServers []string
	cfg, err := c.GetService().GetCfgOpts()
	if err == nil {
		dnsServers = cfg.GetSliceOfStrings("DNSList")
	}
	globalSystemRequirements, err := b.GetGlobalSystemRequirements(c)
	if err != nil {
		done <- err
		return
	}
	data := map[string]interface{}{
		"GlobalSystemRequirements": *globalSystemRequirements,
		"ClusterName":              c.GetIdentity().Name,
		"DNSServerIPs":             dnsServers,
		"MasterIPs":                c.ListMasterIPs(),
	}
	box, err := b.GetTemplateBox()
	if err != nil {
		done <- err
		return
	}
	retcode, _, _, err := b.ExecuteScript(box, funcMap, "swarm_configure_gateway.sh", data, gw.ID)
	if err != nil {
		log.Printf("[gateway] configuration failed: %s", err.Error())
		done <- err
		return
	}
	if retcode != 0 {
		log.Printf("[gateway] configuration failed:\nretcode=%d", retcode)
		done <- fmt.Errorf("scripted gateway configuration failed with error code %d", retcode)
		return
	}

	log.Printf("[gateway] configuration successful")
	done <- nil
}

// asyncCreateMasters ...
// Intended to be used as goroutine
func asyncCreateMasters(
	c api.Cluster, b *Blueprint,
	count int, def pb.HostDefinition, done chan error) {

	fmt.Printf("Creating %d Master%s...\n", count, utils.Plural(count))

	var dones []chan error
	timeout := timeoutCtxHost + time.Duration(count)*time.Minute
	for i := 1; i <= count; i++ {
		d := make(chan error)
		dones = append(dones, d)
		go asyncCreateMaster(c, b, i, def, timeout, d)
	}
	var state error
	var errors []string
	for i := range dones {
		state = <-dones[i]
		if state != nil {
			errors = append(errors, state.Error())
		}
	}
	if len(errors) > 0 {
		done <- fmt.Errorf(strings.Join(errors, "\n"))
		return
	}
	done <- nil
}

func asyncCreateNodes(c api.Cluster, b *Blueprint, count int, public bool, def pb.HostDefinition, done chan error) {
	var nodeType NodeType.Enum
	var nodeTypeStr string
	if public {
		nodeType = NodeType.PublicNode
		nodeTypeStr = "public"
	} else {
		nodeType = NodeType.PrivateNode
		nodeTypeStr = "private"
	}
	fmt.Printf("Creating %d %s Node%s...\n", count, nodeTypeStr, utils.Plural(count))

	var dones []chan error
	var results []chan string
	timeout := timeoutCtxHost + time.Duration(count)*time.Minute
	for i := 1; i <= count; i++ {
		r := make(chan string)
		results = append(results, r)
		d := make(chan error)
		dones = append(dones, d)
		go asyncCreateNode(c, b, i, nodeType, def, timeout, r, d)
	}

	var state error
	var errors []string
	for i := range dones {
		<-results[i]
		state = <-dones[i]
		if state != nil {
			errors = append(errors, state.Error())
		}
	}
	if len(errors) > 0 {
		done <- fmt.Errorf(strings.Join(errors, "\n"))
		return
	}

	done <- nil
}

// asyncCreateNode creates a Node in the Cluster
// This function is intended to be call as a goroutine
func asyncCreateNode(
	c api.Cluster, b *Blueprint,
	index int, nodeType NodeType.Enum, def pb.HostDefinition, timeout time.Duration,
	result chan string, done chan error,
) {

	var publicIP bool
	var nodeTypeStr string
	if nodeType == NodeType.PublicNode {
		nodeTypeStr = "public"
		publicIP = true
	} else {
		nodeTypeStr = "private"
		publicIP = false
	}

	log.Printf("[%s node #%d] starting creation...\n", nodeTypeStr, index)

	// Create the host
	log.Printf("[%s node #%d] starting host resource creation...\n", nodeTypeStr, index)
	var err error
	def.Name, err = c.BuildHostname("node", nodeType)
	if err != nil {
		log.Printf("[%s node #%d] creation failed: %s\n", nodeTypeStr, index, err.Error())
		result <- ""
		done <- err
		return
	}
	def.Public = publicIP
	def.Network = c.GetNetworkConfig().NetworkID
	brokerHost := brokerclient.New().Host
	host, err := brokerHost.Create(def, 10*time.Minute)
	if err != nil {
		err = brokerclient.DecorateError(err, "creation of host resource", true)
		log.Printf("[%s node #%d] creation failed: %s\n", nodeTypeStr, index, err.Error())
		result <- ""
		done <- err
		return
	}

	// Locks for write the NodesV1 extension...
	outerErr := c.GetExtensions().LockForWrite(Extension.NodesV1).ThenUse(func(v interface{}) error {
		nodesV1 := v.(*clusterpropsv1.Nodes)
		// Update Cluster definition in Object Storage
		err := c.UpdateMetadata(func() error {
			// Registers the new Agent in the swarmCluster struct
			node := &clusterpropsv1.Node{
				ID:        host.ID,
				PrivateIP: host.PrivateIP,
				PublicIP:  host.GetPublicIP(),
			}
			if nodeType == NodeType.PublicNode {
				nodesV1.PublicNodes = append(nodesV1.PublicNodes, node)
			} else {
				nodesV1.PrivateNodes = append(nodesV1.PrivateNodes, node)
			}
			return nil
		})
		if err != nil {
			// Removes the ID we just added to the swarmCluster struct
			if nodeType == NodeType.PublicNode {
				nodesV1.PublicNodes = nodesV1.PublicNodes[:len(nodesV1.PublicNodes)-1]
			} else {
				nodesV1.PrivateNodes = nodesV1.PrivateNodes[:len(nodesV1.PrivateNodes)-1]
			}
			return err
		}
		return nil
	})
	if outerErr != nil {
		brokerHost.Delete([]string{host.ID}, brokerclient.DefaultExecutionTimeout)

		log.Printf("[%s node #%d] creation failed: %s", nodeTypeStr, index, err.Error())
		result <- ""
		done <- fmt.Errorf("failed to update Cluster configuration: %s", err.Error())
		return
	}

	log.Printf("[%s node #%d (%s)] host resource created successfully.\n", nodeTypeStr, index, host.Name)
	result <- ""
	done <- nil
}

// asyncConfigureNode ...
func asyncConfigureNode(
	c api.Cluster, b *Blueprint,
	index int, host *pb.Host, nodeType NodeType.Enum, nodeTypeStr string,
	done chan error,
) {

	target := install.NewHostTarget(host)

	//VPL: For now, always disable addition of feature proxycache-client
	err := c.GetExtensions().LockForWrite(Extension.FeaturesV1).ThenUse(func(v interface{}) error {
		v.(clusterpropsv1.Features).Disabled["proxycache-client"] = struct{}{}
		return nil
	})
	if err != nil {
		log.Printf("[%s node #%d (%s)] installation failed:%v", nodeTypeStr, index, host.Name, err)
		done <- err
		return
	}
	//ENDVPL
	doInstall := false
	err = c.GetExtensions().LockForRead(Extension.FeaturesV1).ThenUse(func(v interface{}) error {
		_, doInstall = v.(*clusterpropsv1.Features).Disabled["proxycache"]
		return nil
	})
	if err != nil {
		log.Printf("[%s node #%d (%s)] installation failed:%v", nodeTypeStr, index, host.Name, err)
		done <- err
		return
	}
	if doInstall {
		// install proxycache-client feature
		feature, err := install.NewFeature("proxycache-client")
		if err != nil {
			log.Printf("[%s node #%d (%s)] failed to prepare feature 'proxycache-client': %s", nodeTypeStr, index, host.ID, err.Error())
			done <- fmt.Errorf("failed to install feature 'proxycache-client': %s", err.Error())
			return
		}
		results, err := feature.Add(target, install.Variables{}, install.Settings{})
		if err != nil {
			log.Printf("[%s node #%d (%s)] failed to install feature '%s': %s\n", nodeTypeStr, index, host.Name, feature.DisplayName(), err.Error())
			done <- fmt.Errorf("failed to install feature '%s' on host '%s': %s", feature.DisplayName(), host.Name, err.Error())
			return
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			log.Printf("[%s node #%d (%s)] failed to install feature '%s': %s", nodeTypeStr, index, host.Name, feature.DisplayName(), msg)
			done <- fmt.Errorf(msg)
			return
		}
	}

	// Installs requirements
	log.Printf("[%s node #%d (%s)] installing requirements...\n", nodeTypeStr, index, host.Name)
	globalSystemRequirements, err := b.GetGlobalSystemRequirements(c)
	if err != nil {
		done <- err
		return
	}
	data := map[string]interface{}{
		"GlobalSystemRequirements": *globalSystemRequirements,
	}

	box, err := b.GetTemplateBox()
	if err != nil {
		done <- err
		return
	}
	retcode, _, _, err := b.ExecuteScript(box, funcMap, "swarm_install_node.sh", data, host.ID)
	if err != nil {
		log.Printf("[%s node #%d (%s)] failed to remotely run installation script: %s\n", nodeTypeStr, index, host.Name, err.Error())
		done <- err
		return
	}
	if retcode != 0 {
		log.Printf("[%s node #%d (%s)] installation failed: retcode=%d", nodeTypeStr, index, host.Name, retcode)
		done <- fmt.Errorf("scripted configuration failed with error code %d", retcode)
		return
	}
	log.Printf("[%s node #%d (%s)] requirements installed successfully.\n", nodeTypeStr, index, host.Name)

	// install docker feature
	log.Printf("[%s node #%d (%s)] adding feature 'docker'...\n", nodeTypeStr, index, host.Name)
	feature, err := install.NewFeature("docker")
	if err != nil {
		log.Printf("[%s node #%d (%s)] failed to prepare feature 'docker': %s", nodeTypeStr, index, host.Name, err.Error())
		done <- fmt.Errorf("failed to add feature 'docker': %s", err.Error())
		return
	}
	results, err := feature.Add(target, install.Variables{}, install.Settings{})
	if err != nil {
		log.Printf("[%s node #%d (%s)] failed to add feature '%s': %s\n", nodeTypeStr, index, host.Name, feature.DisplayName(), err.Error())
		done <- fmt.Errorf("failed to add feature '%s' on host '%s': %s", feature.DisplayName(), host.Name, err.Error())
		return
	}
	if !results.Successful() {
		msg := results.AllErrorMessages()
		log.Printf("[%s node #%d (%s)] failed to add feature '%s': %s", nodeTypeStr, index, host.Name, feature.DisplayName(), msg)
		done <- fmt.Errorf("failed to add feature '%s' on host '%s': %s", feature.DisplayName(), host.Name, msg)
		return
	}
	log.Printf("[%s node #%d (%s)] feature 'docker' added successfully.\n", nodeTypeStr, index, host.Name)

	err = b.ConfigureNode(index, host, nodeType, nodeTypeStr)
	if err != nil {
		done <- err
		return
	}

	log.Printf("[%s node #%d (%s)] creation successful.\n", nodeTypeStr, index, host.Name)
	done <- nil
}

// asyncCreateMaster adds a master node
func asyncCreateMaster(
	c api.Cluster, b *Blueprint,
	index int, def pb.HostDefinition, timeout time.Duration, done chan error) {

	log.Printf("[master #%d] starting creation...\n", index)

	name, err := c.BuildHostname("master", NodeType.Master)
	if err != nil {
		log.Printf("[master #%d] creation failed: %s\n", index, err.Error())
		done <- fmt.Errorf("failed to create Master server %d: %s", index, err.Error())
		return
	}

	def.Network = c.GetNetworkConfig().NetworkID
	def.Public = false
	def.Name = name
	brokerHost := brokerclient.New().Host
	host, err := brokerHost.Create(def, timeout)
	if err != nil {
		err = brokerclient.DecorateError(err, "creation of host resource", false)
		log.Printf("[master #%d] host resource creation failed: %s\n", index, err.Error())
		done <- fmt.Errorf("failed to create Master server %d: %s", index, err.Error())
		return
	}

	// Locks for write the Flavor extension...
	outerErr := c.GetExtensions().LockForWrite(Extension.NodesV1).ThenUse(func(v interface{}) error {
		nodesV1 := v.(*clusterpropsv1.Nodes)
		// Update swarmCluster definition in Object Storage
		err := c.UpdateMetadata(func() error {
			node := &clusterpropsv1.Node{
				ID:        host.ID,
				PrivateIP: host.PrivateIP,
				PublicIP:  host.GetPublicIP(),
			}
			nodesV1.Masters = append(nodesV1.Masters, node)
			return nil
		})
		if err != nil {
			// Metadata Storage failed, removes the ID we just added to the swarmCluster struct
			nodesV1.Masters = nodesV1.Masters[:len(nodesV1.Masters)-1]
			return err
		}
		return nil
	})
	if outerErr != nil {
		log.Printf("[master #%d (%s)] creation failed: %s\n", index, host.Name, outerErr.Error())
		done <- fmt.Errorf("failed to update Cluster metadata: %s", outerErr.Error())
		return
	}

	log.Printf("[master #%d (%s)] creation successful\n", index, host.Name)
	done <- nil
}

// asyncConfigureMaster configure DCOS on master
func asyncConfigureMaster(c api.Cluster, b *Blueprint, index int, host *pb.Host, done chan error) {
	log.Debugf("[master #%d (%s)] starting configuration...\n", index, host.Name)

	// Installs cluster-level system requirements...
	log.Debugf("[master #%d (%s)] installing system requirements", index, host.Name)
	globalSystemRequirements, err := b.GetGlobalSystemRequirements(c)
	if err != nil {
		done <- fmt.Errorf("failed to retrieve installation script for master: %s", err.Error())
		return
	}
	data := map[string]interface{}{
		"GlobalSystemRequirements": *globalSystemRequirements,
	}
	box, err := b.GetTemplateBox()
	if err != nil {
		done <- fmt.Errorf("failed to retrieve installation script for master: %s", err.Error())
		return
	}
	retcode, _, _, err := b.ExecuteScript(box, funcMap, "swarm_install_master.sh", data, host.ID)
	if err != nil {
		log.Debugf("[master #%d (%s)] failed to remotely run installation script: %s\n", index, host.Name, err.Error())
		done <- fmt.Errorf("failed to remotely run installation script on host '%s': %s", host.Name, err.Error())
		return
	}
	if retcode != 0 {
		log.Debugf("[master #%d (%s)] installation failed:\nretcode=%d", index, host.ID, retcode)
		done <- fmt.Errorf("scripted Master installation failed with error code %d", retcode)
		return
	}
	log.Debugf("[master #%d (%s)] system requirements successfully installed", index, host.Name)

	values := install.Variables{
		"Password": c.GetIdentity().AdminPassword,
	}

	target := install.NewHostTarget(host)
	//VPL: For now, always disable addition of feature proxy-cache-client
	err = c.GetExtensions().LockForWrite(Extension.FeaturesV1).ThenUse(func(v interface{}) error {
		v.(clusterpropsv1.Features).Disabled["proxycache-client"] = struct{}{}
		return nil
	})
	if err != nil {
		log.Printf("[master #%d (%s)] installation failed:%v", index, host.ID, err)
		done <- err
		return
	}
	doInstall := false
	err = c.GetExtensions().LockForRead(Extension.FeaturesV1).ThenUse(func(v interface{}) error {
		_, doInstall = v.(*clusterpropsv1.Features).Disabled["proxycache-client"]
		return nil
	})
	if err != nil {
		log.Printf("[master #%d (%s)] installation failed:%v", index, host.ID, err)
		done <- err
		return
	}
	if doInstall {
		// install proxycache-client feature
		feature, err := install.NewFeature("proxycache-client")
		if err != nil {
			log.Printf("[master #%d (%s)] failed to prepare feature 'proxycache-client': %s", index, host.Name, err.Error())
			done <- fmt.Errorf("failed to install feature 'proxycache-client': %s", err.Error())
		}
		results, err := feature.Add(target, install.Variables{}, install.Settings{})
		if err != nil {
			log.Printf("[master #%d (%s)] failed to add feature '%s': %s\n", index, host.Name, feature.DisplayName(), err.Error())
			done <- fmt.Errorf("failed to add feature '%s' on host '%s': %s", feature.DisplayName(), host.Name, err.Error())
			return
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			log.Printf("[master #%d (%s)] failed to add feature '%s': %s", 1, host.Name, feature.DisplayName(), msg)
			done <- fmt.Errorf(msg)
			return
		}
	}

	// install docker feature
	log.Printf("[master #%d (%s)] adding feature 'docker'", index, host.Name)
	feature, err := install.NewFeature("docker")
	if err != nil {
		log.Printf("[master #%d (%s)] failed to prepare feature 'docker': %s", index, host.ID, err.Error())
		done <- fmt.Errorf("failed to install feature 'docker': %s", err.Error())
		return
	}
	results, err := feature.Add(target, values, install.Settings{})
	if err != nil {
		log.Printf("[master #%d (%s)] failed to install feature '%s': %s\n", index, host.Name, feature.DisplayName(), err.Error())
		done <- fmt.Errorf("failed to install feature '%s' on host '%s': %s", feature.DisplayName(), host.Name, err.Error())
		return
	}
	if !results.Successful() {
		msg := results.AllErrorMessages()
		log.Printf("[master #%d (%s)] failed to install feature '%s': %s", index, host.Name, feature.DisplayName(), msg)
		done <- fmt.Errorf(msg)
		return
	}
	log.Printf("[master #%d (%s)] feature 'docker' installed successfully\n", index, host.Name)

	err = c.GetExtensions().LockForRead(Extension.FeaturesV1).ThenUse(func(v interface{}) error {
		_, doInstall = v.(*clusterpropsv1.Features).Disabled["remotedesktop"]
		return nil
	})
	if err != nil {
		log.Printf("[master #%d (%s)] installation failed:%v", index, host.ID, err)
		done <- err
		return
	}

	if doInstall {
		// Adds remotedesktop feature on master
		log.Printf("[master #%d (%s)] adding feature 'remotedesktop'\n", index, host.Name)
		feature, err := install.NewFeature("remotedesktop")
		if err != nil {
			log.Printf("[master #%d (%s)] failed to instanciate feature 'remotedesktop': %s\n", index, host.Name, err.Error())
			done <- err
			return
		}
		results, err := feature.Add(target, install.Variables{
			"Username": "cladm",
			"Password": c.GetIdentity().AdminPassword,
		}, install.Settings{})
		if err != nil {
			log.Printf("[master #%d (%s)] failed to add feature '%s': %s", index, host.Name, feature.DisplayName(), err.Error())
			done <- err
			return
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			log.Printf("[master #%d (%s)] addition script of feature '%s' failed: %s\n", index, host.Name, feature.DisplayName(), msg)
			done <- fmt.Errorf(msg)
		}
		log.Printf("[master #%d (%s)] feature '%s' added successfully\n", index, host.Name, feature.DisplayName())
	}

	err = b.ConfigureMaster(index, host)
	if err != nil {
		done <- err
	}

	log.Printf("[master #%d (%s)] configuration successful\n", index, host.Name)
	done <- nil
}

// asyncConfigureMasters configure masters
func asyncConfigureMasters(c api.Cluster, b *Blueprint, done chan error) {
	log.Debugf("Configuring masters...")

	broker := brokerclient.New().Host
	dones := []chan error{}
	for i, hostID := range c.ListMasterIDs() {
		host, err := broker.Inspect(hostID, brokerclient.DefaultExecutionTimeout)
		if err != nil {
			done <- fmt.Errorf("failed to get metadata of host: %s", err.Error())
		}
		d := make(chan error)
		dones = append(dones, d)
		go asyncConfigureMaster(c, b, i+1, host, d)
	}

	var state error
	var errors []string
	for i := range dones {
		state = <-dones[i]
		if state != nil {
			errors = append(errors, state.Error())
		}
	}
	if len(errors) > 0 {
		done <- fmt.Errorf(strings.Join(errors, "\n"))
		return
	}

	done <- nil
}

// asyncConfigureNodes ...
func asyncConfigureNodes(c api.Cluster, b *Blueprint, public bool, done chan error) {
	var (
		nodeType    NodeType.Enum
		nodeTypeStr string
	)
	if public {
		nodeType = NodeType.PrivateNode
		nodeTypeStr = "public"
	} else {
		nodeType = NodeType.PublicNode
		nodeTypeStr = "private"
	}

	log.Debugf("Configuring %s Nodes...", nodeTypeStr)

	var (
		host   *pb.Host
		err    error
		i      int
		hostID string
		errors []string
	)

	list := c.ListNodeIDs(public)
	dones := []chan error{}
	brokerHost := brokerclient.New().Host
	for i, hostID = range list {
		host, err = brokerHost.Inspect(hostID, brokerclient.DefaultExecutionTimeout)
		if err != nil {
			break
		}
		d := make(chan error)
		dones = append(dones, d)
		go asyncConfigureNode(c, b, i+1, host, nodeType, nodeTypeStr, d)
	}
	// Deals with the metadata read failure
	if err != nil {
		errors = append(errors, "failed to get metadata of host '%s': %s", hostID, err.Error())
	}

	for i = range dones {
		err = <-dones[i]
		if err != nil {
			errors = append(errors, err.Error())
		}
	}
	if len(errors) > 0 {
		done <- fmt.Errorf(strings.Join(errors, "\n"))
	} else {
		done <- nil
	}
}
