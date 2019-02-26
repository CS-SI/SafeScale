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
	txttmpl "text/template"

	rice "github.com/GeertJohan/go.rice"

	"github.com/CS-SI/SafeScale/safescale/server/cluster/api"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/controller"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/enums/Complexity"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/enums/NodeType"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/flavors/boh/enums/ErrorCode"
	"github.com/CS-SI/SafeScale/iaas/resources"
	"github.com/CS-SI/SafeScale/utils/template"
)

//go:generate rice embed-go

// const (
// 	timeoutCtxHost = 10 * time.Minute

// 	shortTimeoutSSH = time.Minute
// 	longTimeoutSSH  = 5 * time.Minute

// 	tempFolder = "/var/tmp/"
// )

var (
	// bohTemplateBox is the rice box to use in this package
	bohTemplateBox *rice.Box

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
		GetNodeInstallationScript:   getNodeInstallationScript,
		GetTemplateBox:              getTemplateBox,
		GetGlobalSystemRequirements: getGlobalSystemRequirements,
	}
	return controller.NewBlueprint(c, actors)
}

func minimumRequiredServers(c api.Cluster) (int, int, int) {
	var privateNodeCount int
	switch c.GetIdentity().Complexity {
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
	return "Ubuntu 18.04"
}

// getTemplateBox
func getTemplateBox() (*rice.Box, error) {
	var b *rice.Box
	var err error
	if bohTemplateBox == nil {
		// Note: path MUST be literal for rice to work
		b, err = rice.FindBox("../boh/scripts")
		if err != nil {
			return nil, err
		}
		bohTemplateBox = b
	}
	return bohTemplateBox, nil
}

// getGlobalSystemRequirements returns the string corresponding to the script boh_install_requirements.sh
// which installs common features (docker in particular)
func getGlobalSystemRequirements(c api.Cluster) (*string, error) {
	if globalSystemRequirementsContent == nil {
		// find the rice.Box
		b, err := getTemplateBox()
		if err != nil {
			return nil, err
		}

		// get file contents as string
		tmplString, err := b.String("boh_install_requirements.sh")
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
		data := map[string]interface{}{
			"CIDR":          c.GetNetworkConfig().CIDR,
			"CladmPassword": identity.AdminPassword,
			"SSHPublicKey":  identity.Keypair.PublicKey,
			"SSHPrivateKey": identity.Keypair.PrivateKey,
		}
		err = tmplPrepared.Execute(dataBuffer, data)
		if err != nil {
			return nil, fmt.Errorf("error realizing script template: %s", err.Error())
		}
		result := dataBuffer.String()
		globalSystemRequirementsContent = &result
	}
	return globalSystemRequirementsContent, nil
}

func getNodeInstallationScript(c api.Cluster, nodeType NodeType.Enum) (string, map[string]interface{}) {
	data := map[string]interface{}{}
	script := ""

	switch nodeType {
	case NodeType.Master:
		script = "boh_install_master.sh"
	case NodeType.PrivateNode:
		fallthrough
	case NodeType.PublicNode:
		script = "boh_install_node.sh"
	}
	return script, data
}
