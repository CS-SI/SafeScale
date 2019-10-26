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

package boh

/*
 * Implements a cluster of hosts without cluster management environment
 */

import (
	"bytes"
	"fmt"
	"sync/atomic"
	txttmpl "text/template"

	rice "github.com/GeertJohan/go.rice"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/cluster/control"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/Complexity"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/NodeType"
	"github.com/CS-SI/SafeScale/lib/server/cluster/flavors/boh/enums/ErrorCode"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/template"
)

//go:generate rice embed-go

var (
	// templateBox is the rice box to use in this package
	templateBox atomic.Value

	// funcMap defines the custome functions to be used in templates
	funcMap = txttmpl.FuncMap{
		// The name "inc" is what the function will be called in the template text.
		"inc": func(i int) int {
			return i + 1
		},
		"errcode": func(msg string) int {
			if code, ok := ErrorCode.StringMap[msg]; ok {
				return int(code)
			}
			return 1023
		},
	}

	globalSystemRequirementsContent atomic.Value

	// Makers returns a configured Makers to construct a BOH Cluster
	Makers = control.Makers{
		MinimumRequiredServers:      minimumRequiredServers,
		DefaultGatewaySizing:        gatewaySizing,
		DefaultMasterSizing:         nodeSizing,
		DefaultNodeSizing:           nodeSizing,
		DefaultImage:                defaultImage,
		GetNodeInstallationScript:   getNodeInstallationScript,
		GetTemplateBox:              getTemplateBox,
		GetGlobalSystemRequirements: getGlobalSystemRequirements,
	}
)

func minimumRequiredServers(task concurrency.Task, foreman control.Foreman) (int, int, int) {
	var (
		privateNodeCount int
		masterNodeCount  int
	)
	switch foreman.Cluster().GetIdentity(task).Complexity {
	case Complexity.Small:
		privateNodeCount = 1
		masterNodeCount = 1
	case Complexity.Normal:
		privateNodeCount = 3
		masterNodeCount = 2
	case Complexity.Large:
		privateNodeCount = 7
		masterNodeCount = 3
	}
	return masterNodeCount, privateNodeCount, 0
}

func gatewaySizing(task concurrency.Task, foreman control.Foreman) pb.HostDefinition {
	return pb.HostDefinition{
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

func nodeSizing(task concurrency.Task, foreman control.Foreman) pb.HostDefinition {
	return pb.HostDefinition{
		Sizing: &pb.HostSizing{
			MinCpuCount: 2,
			MaxCpuCount: 4,
			MinRamSize:  15.0,
			MaxRamSize:  32.0,
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
	var (
		b   *rice.Box
		err error
	)
	anon := templateBox.Load()
	if anon == nil {
		// Note: path MUST be literal for rice to work
		b, err = rice.FindBox("../boh/scripts")
		if err != nil {
			return nil, err
		}
		templateBox.Store(b)
		anon = templateBox.Load()
	}
	return anon.(*rice.Box), nil
}

// getGlobalSystemRequirements returns the string corresponding to the script boh_install_requirements.sh
// which installs common features (docker in particular)
func getGlobalSystemRequirements(task concurrency.Task, foreman control.Foreman) (string, error) {
	anon := globalSystemRequirementsContent.Load()
	if anon == nil {
		// find the rice.Box
		b, err := getTemplateBox()
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
		tmplString, err := b.String("boh_install_requirements.sh")
		if err != nil {
			return "", fmt.Errorf("error loading script template: %s", err.Error())
		}

		// parse then execute the template
		tmplPrepared, err := txttmpl.New("install_requirements").Funcs(template.MergeFuncs(funcMap, false)).Parse(tmplString)
		if err != nil {
			return "", fmt.Errorf("error parsing script template: %s", err.Error())
		}
		dataBuffer := bytes.NewBufferString("")
		identity := cluster.GetIdentity(task)
		data := map[string]interface{}{
			"CIDR":          netCfg.CIDR,
			"CladmPassword": identity.AdminPassword,
			"SSHPublicKey":  identity.Keypair.PublicKey,
			"SSHPrivateKey": identity.Keypair.PrivateKey,
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

func getNodeInstallationScript(task concurrency.Task, foreman control.Foreman, nodeType NodeType.Enum) (string, map[string]interface{}) {
	data := map[string]interface{}{}
	script := ""

	switch nodeType {
	case NodeType.Master:
		script = "boh_install_master.sh"
	case NodeType.Node:
		script = "boh_install_node.sh"
	}
	return script, data
}
