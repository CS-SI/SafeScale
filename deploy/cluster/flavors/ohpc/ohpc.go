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

package ohpc

/*
 * Implements a cluster of hosts without cluster management environment
 */

import (
	"bytes"
	"fmt"
	"time"

	txttmpl "text/template"
	// log "github.com/sirupsen/logrus"
	rice "github.com/GeertJohan/go.rice"

	"github.com/CS-SI/SafeScale/deploy/cluster/api"
	"github.com/CS-SI/SafeScale/deploy/cluster/controller"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Complexity"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/NodeType"
	"github.com/CS-SI/SafeScale/deploy/cluster/flavors/ohpc/enums/ErrorCode"
	"github.com/CS-SI/SafeScale/deploy/install"
	"github.com/CS-SI/SafeScale/iaas/resources"
	"github.com/CS-SI/SafeScale/utils/template"
)

//go:generate rice embed-go

const (
	timeoutCtxHost = 10 * time.Minute

	shortTimeoutSSH = time.Minute
	longTimeoutSSH  = 5 * time.Minute

	tempFolder = "/var/tmp/"

	centos = "CentOS 7.4"
)

var (
	// templateBox is the rice box to use in this package
	templateBox *rice.Box

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

	globalSystemRequirementsContent *string
)

// Blueprint returns a configured blueprint to construct a BOH Cluster
func Blueprint(c *controller.Controller) *controller.Blueprint {
	actors := controller.BlueprintActors{
		MinimumRequiredServers:      minimumRequiredServers,
		DefaultGatewaySizing:        gatewaySizing,
		DefaultMasterSizing:         nodeSizing,
		DefaultNodeSizing:           nodeSizing,
		DefaultImage:                defaultImage,
		GetTemplateBox:              getTemplateBox,
		GetGlobalSystemRequirements: getGlobalSystemRequirements,
		GetNodeInstallationScript:   getNodeInstallationScript,
	}
	return controller.NewBlueprint(c, actors)
}

func minimumRequiredServers(c api.Cluster) (int, int, int) {
	complexity := c.GetIdentity().Complexity
	privateNodeCount := 0

	switch complexity {
	case Complexity.Small:
		privateNodeCount = 1
	case Complexity.Normal:
		privateNodeCount = 3
	case Complexity.Large:
		privateNodeCount = 7
	}

	return 1, privateNodeCount, 0
}

func gatewaySizing(c api.Cluster) resources.HostDefinition {
	return resources.HostDefinition{
		Cores:    2,
		RAMSize:  15.0,
		DiskSize: 60,
	}
}

func nodeSizing(c api.Cluster) resources.HostDefinition {
	return resources.HostDefinition{
		Cores:    4,
		RAMSize:  15.0,
		DiskSize: 100,
	}
}

func defaultImage(c api.Cluster) string {
	return centos
}

func configureCluster(c api.Cluster) error {
	// Install feature ohpc-slurm-master on cluster...
	feature, err := install.NewFeature("ohpc-slurm-master")
	if err != nil {
		return err
	}
	target := install.NewClusterTarget(c)
	list := c.ListMasterIPs()
	values := install.Variables{
		"PrimaryMasterIP":   list[0],
		"SecondaryMasterIP": "",
	}
	if len(list) > 1 {
		values["SecondaryMasterIP"] = list[1]
	}
	results, err := feature.Add(target, values, install.Settings{})
	if err != nil {
		return err
	}
	if !results.Successful() {
		return fmt.Errorf(results.AllErrorMessages())
	}

	// Install feature ohpc-slurm-node on cluster...
	feature, err = install.NewFeature("ohpc-slurm-node")
	if err != nil {
		return err
	}
	results, err = feature.Add(target, values, install.Settings{})
	if err != nil {
		return err
	}
	if !results.Successful() {
		return fmt.Errorf(results.AllErrorMessages())
	}
	return nil
}

func getNodeInstallationScript(c api.Cluster, nodeType NodeType.Enum) (string, map[string]interface{}) {
	script := ""
	data := map[string]interface{}{}
	switch nodeType {
	case NodeType.Gateway:
	case NodeType.Master:
		script = "ohpc_install_master.sh"
	case NodeType.PrivateNode:
		fallthrough
	case NodeType.PublicNode:
		script = "ohpc_install_node.sh"
	}

	return script, data
}

func getTemplateBox() (*rice.Box, error) {
	if templateBox == nil {
		// Note: path MUST be literal for rice to work
		b, err := rice.FindBox("../ohpc/scripts")
		if err != nil {
			return nil, err
		}
		templateBox = b
	}
	return templateBox, nil
}

func getGlobalSystemRequirements(c api.Cluster) (*string, error) {
	if globalSystemRequirementsContent == nil {
		// find the rice.Box
		box, err := getTemplateBox()
		if err != nil {
			return nil, err
		}

		// get file contents as string
		tmplString, err := box.String("ohpc_install_requirements.sh")
		if err != nil {
			return nil, fmt.Errorf("error loading script template: %s", err.Error())
		}

		// parse then execute the template
		tmplPrepared, err := txttmpl.New("install_requirements").Funcs(template.MergeFuncs(funcMap, false)).Parse(tmplString)
		if err != nil {
			return nil, fmt.Errorf("error parsing script template: %s", err.Error())
		}
		dataBuffer := bytes.NewBufferString("")
		identity := c.GetIdentity()
		err = tmplPrepared.Execute(dataBuffer, map[string]interface{}{
			"CIDR":          c.GetNetworkConfig().CIDR,
			"CladmPassword": identity.AdminPassword,
			"SSHPublicKey":  identity.Keypair.PublicKey,
			"SSHPrivateKey": identity.Keypair.PrivateKey,
		})
		if err != nil {
			return nil, fmt.Errorf("error realizing script template: %s", err.Error())
		}
		result := dataBuffer.String()
		globalSystemRequirementsContent = &result
	}
	return globalSystemRequirementsContent, nil
}
