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

package k8s

import (
	"bytes"
	"fmt"
	"sync/atomic"

	txttmpl "text/template"

	rice "github.com/GeertJohan/go.rice"
	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/iaas/resources"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/control"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/enums/Complexity"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/enums/NodeType"
	"github.com/CS-SI/SafeScale/safescale/server/install"
	"github.com/CS-SI/SafeScale/utils/concurrency"
)

//go:generate rice embed-go

var (
	templateBox                     atomic.Value
	globalSystemRequirementsContent atomic.Value

	// Makers initializes a control.Makers struct to construct a BOH Cluster
	Makers = control.Makers{
		MinimumRequiredServers:      minimumRequiredServers,
		DefaultGatewaySizing:        gatewaySizing,
		DefaultMasterSizing:         nodeSizing,
		DefaultNodeSizing:           nodeSizing,
		DefaultImage:                defaultImage,
		GetTemplateBox:              getTemplateBox,
		GetGlobalSystemRequirements: getGlobalSystemRequirements,
		GetNodeInstallationScript:   getNodeInstallationScript,
		ConfigureCluster:            configureCluster,
	}
)

func minimumRequiredServers(task concurrency.Task, foreman control.Foreman) (int, int, int) {
	complexity := foreman.Cluster().GetIdentity(task).Complexity
	masterCount := 0
	privateNodeCount := 0
	publicNodeCount := 0

	switch complexity {
	case Complexity.Small:
		masterCount = 1
		privateNodeCount = 1
	case Complexity.Normal:
		masterCount = 3
		privateNodeCount = 3
	case Complexity.Large:
		masterCount = 5
		privateNodeCount = 6
	}
	return masterCount, privateNodeCount, publicNodeCount
}

func gatewaySizing(task concurrency.Task, foreman control.Foreman) resources.HostDefinition {
	return resources.HostDefinition{
		Cores:    2,
		RAMSize:  15.0,
		DiskSize: 60,
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

func configureCluster(task concurrency.Task, foreman control.Foreman) error {
	clusterName := foreman.Cluster().GetIdentity(task).Name
	log.Println(fmt.Sprintf("[cluster %s] adding feature 'kubernetes'...", clusterName))

	target := install.NewClusterTarget(task, foreman.Cluster())
	feature, err := install.NewFeature(task, "kubernetes")
	if err != nil {
		log.Errorf("[cluster %s] failed to instanciate feature 'kubernetes': %v", clusterName, err)
		return fmt.Errorf("failed to prepare feature 'kubernetes': %s", err.Error())
	}
	results, err := feature.Add(target, install.Variables{}, install.Settings{})
	if err != nil {
		log.Errorf("[cluster %s] failed to add feature 'kubernetes': %s", clusterName, err.Error())
		return err
	}
	if !results.Successful() {
		err = fmt.Errorf(results.AllErrorMessages())
		log.Errorf("[cluster %s] failed to add feature 'kubernetes': %s", clusterName, err.Error())
		return err
	}
	log.Println(fmt.Sprintf("[cluster %s] feature 'kubernetes' addition successful.", clusterName))
	return nil
}

func getNodeInstallationScript(task concurrency.Task, foreman control.Foreman, nodeType NodeType.Enum) (string, map[string]interface{}) {
	script := ""
	data := map[string]interface{}{}

	switch nodeType {
	case NodeType.Gateway:
	case NodeType.Master:
		script = "k8s_install_master.sh"
	case NodeType.PrivateNode:
		fallthrough
	case NodeType.PublicNode:
		script = "k8s_install_node.sh"
	}
	return script, data
}

func getTemplateBox() (*rice.Box, error) {
	anon := templateBox.Load()
	if anon == nil {
		// Note: path MUST be literal for rice to work
		b, err := rice.FindBox("../k8s/scripts")
		if err != nil {
			return nil, err
		}
		templateBox.Store(b)
		anon = templateBox.Load()
	}
	return anon.(*rice.Box), nil
}

func getGlobalSystemRequirements(task concurrency.Task, foreman control.Foreman) (*string, error) {
	anon := globalSystemRequirementsContent.Load()
	if anon == nil {
		// find the rice.Box
		box, err := getTemplateBox()
		if err != nil {
			return nil, err
		}

		// get file contents as string
		tmplString, err := box.String("k8s_install_requirements.sh")
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
		err = tmplPrepared.Execute(dataBuffer, map[string]interface{}{
			"CIDR":          cluster.GetNetworkConfig(task).CIDR,
			"Username":      "cladm",
			"CladmPassword": identity.AdminPassword,
			"SSHPublicKey":  identity.Keypair.PublicKey,
			"SSHPrivateKey": identity.Keypair.PrivateKey,
		})
		if err != nil {
			return nil, fmt.Errorf("error realizing script template: %s", err.Error())
		}
		result := dataBuffer.String()
		globalSystemRequirementsContent.Store(&result)
		anon = globalSystemRequirementsContent.Load()
	}
	return anon.(*string), nil
}
