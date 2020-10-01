/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"sync/atomic"

	rice "github.com/GeertJohan/go.rice"
	// log "github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/cluster/control"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/complexity"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/nodetype"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/template"
)

//go:generate rice embed-go

var (
	templateBox atomic.Value

	// GlobalSystemRequirementsContent *string
	globalSystemRequirementsContent atomic.Value

	// Makers initializes a control.Makers struct to construct a Docker Swarm Cluster
	Makers = control.Makers{
		MinimumRequiredServers:      minimumRequiredServers,
		DefaultGatewaySizing:        gatewaySizing,
		DefaultMasterSizing:         masterSizing,
		DefaultNodeSizing:           nodeSizing,
		DefaultImage:                defaultImage,
		GetTemplateBox:              getTemplateBox,
		GetGlobalSystemRequirements: getGlobalSystemRequirements,
		GetNodeInstallationScript:   getNodeInstallationScript,
	}
)

func minimumRequiredServers(task concurrency.Task, foreman control.Foreman) (int, int, int) {
	var masterCount, privateNodeCount int
	switch foreman.Cluster().GetIdentity(task).Complexity {
	case complexity.Small:
		masterCount = 1
		privateNodeCount = 1
	case complexity.Normal:
		masterCount = 3
		privateNodeCount = 3
	case complexity.Large:
		masterCount = 5
		privateNodeCount = 3
	}
	return masterCount, privateNodeCount, 0
}

func gatewaySizing(task concurrency.Task, foreman control.Foreman) *pb.HostDefinition {
	return &pb.HostDefinition{
		Sizing: &pb.HostSizing{
			MinCpuCount: 2,
			MaxCpuCount: 4,
			MinRamSize:  7.0,
			MaxRamSize:  16.0,
			MinDiskSize: 50,
			GpuCount:    -1,
		},
	}
}

func masterSizing(task concurrency.Task, foreman control.Foreman) *pb.HostDefinition {
	return &pb.HostDefinition{
		Sizing: &pb.HostSizing{
			MinCpuCount: 4,
			MaxCpuCount: 8,
			MinRamSize:  7.0,
			MaxRamSize:  16.0,
			MinDiskSize: 80,
			GpuCount:    -1,
		},
	}
}

func nodeSizing(task concurrency.Task, foreman control.Foreman) *pb.HostDefinition {
	return &pb.HostDefinition{
		Sizing: &pb.HostSizing{
			MinCpuCount: 4,
			MaxCpuCount: 8,
			MinRamSize:  7.0,
			MaxRamSize:  16.0,
			MinDiskSize: 80,
			GpuCount:    -1,
		},
	}
}

func defaultImage(task concurrency.Task, foreman control.Foreman) string {
	return "Ubuntu 18.04"
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
// which installs common features
func getGlobalSystemRequirements(task concurrency.Task, foreman control.Foreman) (string, error) {
	anon := globalSystemRequirementsContent.Load()
	if anon == nil {
		// find the rice.Box
		box, err := getTemplateBox()
		if err != nil {
			return "", err
		}

		// We will need information about cluster network
		cluster := foreman.Cluster()
		netCfg, err := cluster.GetNetworkConfig(task)
		if err != nil {
			return "", err
		}

		// get file contents as string
		tmplString, err := box.String("swarm_install_requirements.sh")
		if err != nil {
			return "", fmt.Errorf("error loading script template: %s", err.Error())
		}

		// parse then execute the template
		// tmplPrepared, err := txttmpl.New("install_requirements").Funcs(template.MergeFuncs(nil, false)).Parse(tmplString)
		tmplPrepared, err := template.Parse("install_requirements", tmplString, nil)
		if err != nil {
			return "", fmt.Errorf("error parsing script template: %s", err.Error())
		}
		dataBuffer := bytes.NewBufferString("")
		identity := cluster.GetIdentity(task)
		data := map[string]interface{}{
			"CIDR":                 netCfg.CIDR,
			"ClusterAdminUsername": "cladm",
			"ClusterAdminPassword": identity.AdminPassword,
			"SSHPublicKey":         identity.Keypair.PublicKey,
			"SSHPrivateKey":        identity.Keypair.PrivateKey,
		}
		err = tmplPrepared.Execute(dataBuffer, data)
		if err != nil {
			return "", fmt.Errorf("error realizing script template: %s", err.Error())
		}
		globalSystemRequirementsContent.Store(dataBuffer.String())
		anon = globalSystemRequirementsContent.Load()
	}
	return anon.(string), nil
}

func getNodeInstallationScript(task concurrency.Task, foreman control.Foreman, hostType nodetype.Enum) (string, map[string]interface{}) {
	script := ""
	data := map[string]interface{}{}

	switch hostType {
	case nodetype.Master:
		script = "swarm_install_master.sh"
	case nodetype.Gateway, nodetype.Node:
		script = "swarm_install_node.sh"
	}
	return script, data
}
