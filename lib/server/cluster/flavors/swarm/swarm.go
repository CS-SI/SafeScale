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

package swarm

/*
 * Implements a swarmCluster of hosts without swarmCluster management environment
 */

import (
	"bytes"
	"fmt"
	"github.com/CS-SI/SafeScale/lib/utils"
	"strings"
	"sync/atomic"
	txttmpl "text/template"

	rice "github.com/GeertJohan/go.rice"
	// log "github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/server/cluster/control"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/Complexity"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/NodeType"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
)

//go:generate rice embed-go

const (
	// tempFolder = "/opt/safescale/var/tmp/"
)

var (
	templateBox atomic.Value

	// GlobalSystemRequirementsContent *string
	globalSystemRequirementsContent atomic.Value

	// Makers initializes a control.Makers struct to construct a Docker Swarm Cluster
	Makers = control.Makers{
		MinimumRequiredServers:      minimumRequiredServers,
		DefaultGatewaySizing:        gatewaySizing,
		DefaultNodeSizing:           nodeSizing,
		DefaultImage:                defaultImage,
		UnconfigureNode:             unconfigureNode,
		ConfigureCluster:            configureCluster,
		JoinNodeToCluster:           joinNode,
		JoinMasterToCluster:         joinMaster,
		GetTemplateBox:              getTemplateBox,
		GetGlobalSystemRequirements: getGlobalSystemRequirements,
		GetNodeInstallationScript:   getNodeInstallationScript,
	}
)

func minimumRequiredServers(task concurrency.Task, foreman control.Foreman) (int, int, int) {
	var masterCount, privateNodeCount int
	complexity := foreman.Cluster().GetIdentity(task).Complexity
	switch complexity {
	case Complexity.Small:
		masterCount = 1
		privateNodeCount = 1
	case Complexity.Normal:
		masterCount = 3
		privateNodeCount = 3
	case Complexity.Large:
		masterCount = 5
		privateNodeCount = 3
	}
	return masterCount, privateNodeCount, 0
}

func gatewaySizing(task concurrency.Task, foreman control.Foreman) resources.HostDefinition {
	return resources.HostDefinition{
		Cores:    2,
		RAMSize:  15.0,
		DiskSize: 60,
	}
}

func masterSizing(task concurrency.Task, foreman control.Foreman) resources.HostDefinition {
	return resources.HostDefinition{
		Cores:    4,
		RAMSize:  15.0,
		DiskSize: 100,
	}
}

func nodeSizing(task concurrency.Task, foreman control.Foreman) resources.HostDefinition {
	return resources.HostDefinition{
		Cores:    4,
		RAMSize:  15.0,
		DiskSize: 100,
	}
}

func defaultImage(task concurrency.Task, foreman control.Foreman) string {
	return "Ubuntu 18.04"
}

// configureCluster configures cluster
func configureCluster(task concurrency.Task, foreman control.Foreman) error {
	clientInstance := client.New()
	clientHost := clientInstance.Host
	clientSSH := clientInstance.Ssh

	cluster := foreman.Cluster()

	// Join masters in Docker Swarm as managers
	joinCmd := ""
	for _, hostID := range cluster.ListMasterIDs(task) {
		host, err := clientHost.Inspect(hostID, client.DefaultExecutionTimeout)
		if err != nil {
			return fmt.Errorf("failed to get metadata of host: %s", err.Error())
		}
		if joinCmd == "" {
			retcode, _, _, err := clientSSH.Run(hostID, "docker swarm init",
				client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
			if err != nil || retcode != 0 {
				return fmt.Errorf("failed to init docker swarm")
			}
			retcode, token, stderr, err := clientSSH.Run(hostID, "docker swarm join-token manager -q",
				client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
			if err != nil || retcode != 0 {
				return fmt.Errorf("failed to generate token to join swarm as manager: %s", stderr)
			}
			token = strings.Trim(token, "\n")
			joinCmd = fmt.Sprintf("docker swarm join --token %s %s", token, host.PrivateIp)
		} else {
			retcode, _, stderr, err := clientSSH.Run(hostID, joinCmd,
				client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
			if err != nil || retcode != 0 {
				return fmt.Errorf("failed to join host '%s' to swarm as manager: %s", host.Name, stderr)
			}
		}
	}

	// build command to join Docker Swarm as workers
	joinCmd, err := getSwarmJoinCommand(task, foreman, true)
	if err != nil {
		return err
	}

	// Join private node in Docker Swarm as workers
	for _, hostID := range cluster.ListNodeIDs(task) {
		host, err := clientHost.Inspect(hostID, client.DefaultExecutionTimeout)
		if err != nil {
			return fmt.Errorf("failed to get metadata of host: %s", err.Error())
		}
		retcode, _, stderr, err := clientSSH.Run(hostID, joinCmd,
			client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
		if err != nil || retcode != 0 {
			return fmt.Errorf("failed to join host '%s' to swarm as worker: %s", host.Name, stderr)
		}
	}

	return nil
}

// joinMaster is the code to use to join a new master to the cluster
func joinMaster(task concurrency.Task, foreman control.Foreman, pbHost *pb.Host) error {
	clientSSH := client.New().Ssh

	joinCmd, err := getSwarmJoinCommand(task, foreman, false)
	if err != nil {
		return err
	}
	retcode, _, stderr, err := clientSSH.Run(pbHost.Id, joinCmd,
		client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
	if err != nil || retcode != 0 {
		return fmt.Errorf("failed to join host '%s' to swarm as manager: %s", pbHost.Name, stderr)
	}

	return nil
}

// joinNode is the code to use join a new node to the cluster
func joinNode(task concurrency.Task, foreman control.Foreman, pbHost *pb.Host) error {
	clientSSH := client.New().Ssh

	joinCmd, err := getSwarmJoinCommand(task, foreman, true)
	if err != nil {
		return err
	}
	retcode, _, stderr, err := clientSSH.Run(pbHost.Id, joinCmd,
		client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
	if err != nil || retcode != 0 {
		return fmt.Errorf("failed to join host '%s' to swarm as worker: %s", pbHost.Name, stderr)
	}
	return nil
}

// getSwarmToken obtains token to join Docker Swarm as workers
func getSwarmJoinCommand(task concurrency.Task, foreman control.Foreman, worker bool) (string, error) {
	masterID, err := foreman.Cluster().FindAvailableMaster(task)
	if err != nil {
		return "", fmt.Errorf("failed to join workers to Docker Swarm: %v", err)
	}
	clientInstance := client.New()
	master, err := clientInstance.Host.Inspect(masterID, client.DefaultExecutionTimeout)
	if err != nil {
		return "", fmt.Errorf("failed to get metadata of master: %s", err.Error())
	}
	memberType := "manager"
	if worker {
		memberType = "worker"
	}
	tokenCmd := fmt.Sprintf("docker swarm join-token %s -q", memberType)
	retcode, token, stderr, err := clientInstance.Ssh.Run(masterID, tokenCmd,
		client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
	if err != nil || retcode != 0 {
		return "", fmt.Errorf("failed to generate token to join swarm as worker: %s", stderr)
	}
	token = strings.Trim(token, "\n")
	return fmt.Sprintf("docker swarm join --token %s %s", token, master.PrivateIp), nil
}

// getTemplateBox
func getTemplateBox() (*rice.Box, error) {
	anon := templateBox.Load()
	if anon == nil {
		// Note: path MUST be literal for rice to work
		b, err := rice.FindBox("../swarm/scripts")
		if err != nil {
			return nil, err
		}
		templateBox.Store(b)
		anon = templateBox.Load()
	}
	return anon.(*rice.Box), nil
}

// getGlobalSystemRequirements returns the string corresponding to the script swarm_install_requirements.sh
// which installs common features (docker in particular)
func getGlobalSystemRequirements(task concurrency.Task, foreman control.Foreman) (*string, error) {
	anon := globalSystemRequirementsContent.Load()
	if anon == nil {
		// find the rice.Box
		box, err := getTemplateBox()
		if err != nil {
			return nil, err
		}

		// get file contents as string
		tmplString, err := box.String("swarm_install_requirements.sh")
		if err != nil {
			return nil, fmt.Errorf("error loading script template: %s", err.Error())
		}

		// parse then execute the template
		tmplPrepared, err := txttmpl.New("install_requirements").Parse(tmplString)
		if err != nil {
			return nil, fmt.Errorf("error parsing script template: %s", err.Error())
		}
		dataBuffer := bytes.NewBufferString("")
		cluster := foreman.Cluster()
		identity := cluster.GetIdentity(task)
		data := map[string]interface{}{
			"CIDR":          cluster.GetNetworkConfig(task).CIDR,
			"CladmPassword": identity.AdminPassword,
			"SSHPublicKey":  identity.Keypair.PublicKey,
			"SSHPrivateKey": identity.Keypair.PrivateKey,
		}
		err = tmplPrepared.Execute(dataBuffer, data)
		if err != nil {
			return nil, fmt.Errorf("error realizing script template: %s", err.Error())
		}
		result := dataBuffer.String()
		globalSystemRequirementsContent.Store(&result)
		anon = globalSystemRequirementsContent.Load()
	}
	return anon.(*string), nil
}

func unconfigureNode(task concurrency.Task, foreman control.Foreman, pbHost *pb.Host, selectedMaster string) error {
	if foreman == nil {
		panic("c is nil!")
	}
	if pbHost == nil {
		panic("pbHost is nil!")
	}
	if selectedMaster == "" {
		var err error
		selectedMaster, err = foreman.Cluster().FindAvailableMaster(task)
		if err != nil {
			return err
		}
	}

	clientSSH := client.New().Ssh

	// Check worker is member of the Swarm
	cmd := fmt.Sprintf("docker node ls --format \"{{.Hostname}}\" --filter \"name=%s\" | grep -i %s", pbHost.Name, pbHost.Name)
	retcode, _, _, err := clientSSH.Run(selectedMaster, cmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
	if err != nil {
		return err
	}
	if retcode != 0 {
		// node is already expelled from Docker Swarm
		return nil
	}
	// node is a worker in the Swarm: 1st ask worker to leave Swarm
	cmd = "docker swarm leave"
	retcode, _, stderr, err := clientSSH.Run(pbHost.Id, cmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fmt.Errorf("failed to make node '%s' leave swarm: %s", pbHost.Name, stderr)
	}

	// 2nd: wait the Swarm worker to appear as down from Swarm master
	cmd = fmt.Sprintf("docker node ls --format \"{{.Status}}\" --filter \"name=%s\" | grep -i down", pbHost.Name)
	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			retcode, _, _, err := clientSSH.Run(selectedMaster, cmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
			if err != nil {
				return err
			}
			if retcode != 0 {
				return fmt.Errorf("'%s' not in Down state", pbHost.Name)
			}
			return nil
		},
		utils.GetHostTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case retry.ErrTimeout:
			return fmt.Errorf("Swarm worker '%s' didn't reach 'Down' state after %v", pbHost.Name, utils.GetHostTimeout())
		default:
			return fmt.Errorf("Swarm worker '%s' didn't reach 'Down' state: %v", pbHost.Name, retryErr)
		}
	}

	// 3rd, ask master to remove node from Swarm
	cmd = fmt.Sprintf("docker node rm %s", pbHost.Name)
	retcode, _, stderr, err = clientSSH.Run(selectedMaster, cmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fmt.Errorf("failed to remove worker '%s' from Swarm on master '%s': %s", pbHost.Name, selectedMaster, stderr)
	}
	return nil
}

func getNodeInstallationScript(task concurrency.Task, foreman control.Foreman, hostType NodeType.Enum) (string, map[string]interface{}) {
	script := ""
	data := map[string]interface{}{}

	switch hostType {
	case NodeType.Gateway:
		script = "swarm_install_gateway.sh"
	case NodeType.Master:
		script = "swarm_install_master.sh"
	case NodeType.Node:
		script = "swarm_install_node.sh"
	}
	return script, data
}
