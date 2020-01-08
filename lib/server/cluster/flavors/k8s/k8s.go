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
	"strconv"
	"strings"
	"sync/atomic"

	txttmpl "text/template"

	rice "github.com/GeertJohan/go.rice"
	"github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/server/cluster/control"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/complexity"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/nodetype"
	"github.com/CS-SI/SafeScale/lib/server/install"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
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
		LeaveNodeFromCluster:        leaveNodeFromCluster,
	}
)

func minimumRequiredServers(task concurrency.Task, foreman control.Foreman) (int, int, int) {
	masterCount := 0
	privateNodeCount := 0
	publicNodeCount := 0

	switch foreman.Cluster().GetIdentity(task).Complexity {
	case complexity.Small:
		masterCount = 1
		privateNodeCount = 1
	case complexity.Normal:
		masterCount = 3
		privateNodeCount = 3
	case complexity.Large:
		masterCount = 5
		privateNodeCount = 6
	}
	return masterCount, privateNodeCount, publicNodeCount
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
			MinCpuCount: 4,
			MaxCpuCount: 8,
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

func configureCluster(task concurrency.Task, foreman control.Foreman, req control.Request) error {
	clusterName := foreman.Cluster().GetIdentity(task).Name
	logrus.Println(fmt.Sprintf("[cluster %s] adding feature 'kubernetes'...", clusterName))

	target, err := install.NewClusterTarget(task, foreman.Cluster())
	if err != nil {
		return err
	}
	feature, err := install.NewFeature(task, "kubernetes")
	if err != nil {
		logrus.Errorf("[cluster %s] failed to instantiate feature 'kubernetes': %v", clusterName, err)
		return fmt.Errorf("failed to prepare feature 'kubernetes': %s", err.Error())
	}

	// Initializes variables
	v := install.Variables{}

	// If hardening is disabled, set the appropriate parameter of the kubernetes feature
	if _, ok := req.DisabledDefaultFeatures["hardening"]; ok {
		v["Hardening"] = strconv.FormatBool(!ok)
	}

	// Disable dashboard if requested
	if _, ok := req.DisabledDefaultFeatures["dashboard"]; ok {
		v["Dashboard"] = strconv.FormatBool(!ok)
	}

	// Installs kubernetes feature
	results, err := feature.Add(target, v, install.Settings{})
	if err != nil {
		logrus.Errorf("[cluster %s] failed to add feature 'kubernetes': %s", clusterName, err.Error())
		return err
	}
	if !results.Successful() {
		err = fmt.Errorf(results.AllErrorMessages())
		logrus.Errorf("[cluster %s] failed to add feature 'kubernetes': %s", clusterName, err.Error())
		return err
	}
	logrus.Println(fmt.Sprintf("[cluster %s] feature 'kubernetes' addition successful.", clusterName))
	return nil
}

func getNodeInstallationScript(task concurrency.Task, foreman control.Foreman, nodeType nodetype.Enum) (string, map[string]interface{}) {
	script := ""
	theData := map[string]interface{}{}

	switch nodeType {
	case nodetype.Gateway:
	case nodetype.Master:
		script = "k8s_install_master.sh"
	case nodetype.Node:
		script = "k8s_install_node.sh"
	}
	return script, theData
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

func getGlobalSystemRequirements(task concurrency.Task, foreman control.Foreman) (string, error) {
	anon := globalSystemRequirementsContent.Load()
	if anon == nil {
		// find the rice.Box
		box, err := getTemplateBox()
		if err != nil {
			return "", err
		}

		// We will need information from cluster network
		cluster := foreman.Cluster()
		netCfg, err := cluster.GetNetworkConfig(task)
		if err != nil {
			return "", err
		}

		// get file contents as string
		tmplString, err := box.String("k8s_install_requirements.sh")
		if err != nil {
			return "", fmt.Errorf("error loading script template: %s", err.Error())
		}

		// parse then execute the template
		tmplPrepared, err := txttmpl.New("install_requirements").Parse(tmplString)
		if err != nil {
			return "", fmt.Errorf("error parsing script template: %s", err.Error())
		}
		dataBuffer := bytes.NewBufferString("")
		identity := cluster.GetIdentity(task)
		err = tmplPrepared.Execute(dataBuffer, map[string]interface{}{
			"CIDR":                 netCfg.CIDR,
			"ClusterAdminUsername": "cladm",
			"ClusterAdminPassword": identity.AdminPassword,
			"SSHPublicKey":         identity.Keypair.PublicKey,
			"SSHPrivateKey":        identity.Keypair.PrivateKey,
		})
		if err != nil {
			return "", fmt.Errorf("error realizing script template: %s", err.Error())
		}
		globalSystemRequirementsContent.Store(dataBuffer.String())
		anon = globalSystemRequirementsContent.Load()
	}
	return anon.(string), nil
}

func leaveNodeFromCluster(task concurrency.Task, b control.Foreman, pbHost *pb.Host, selectedMaster string) error {
	if selectedMaster == "" {
		var err error
		selectedMaster, err = b.Cluster().FindAvailableMaster(task)
		if err != nil {
			return err
		}
	}

	clientSSH := client.New().SSH

	// Check worker belongs to k8s
	cmd := fmt.Sprintf("sudo -u cladm -i kubectl get node --selector='!node-role.kubernetes.io/master' | tail -n +2")
	retcode, retout, _, err := clientSSH.Run(selectedMaster, cmd, outputs.COLLECT, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fmt.Errorf("error listing k8s nodes %s: errorcode %d", pbHost.Name, retcode)
	}
	if !strings.Contains(retout, pbHost.Name) {
		return nil // not there, nothing to do
	}

	cmd = fmt.Sprintf("sudo -u cladm -i kubectl drain %s --delete-local-data --force --ignore-daemonsets", pbHost.Name)
	retcode, _, _, err = clientSSH.Run(selectedMaster, cmd, outputs.COLLECT, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fmt.Errorf("error draining k8s node %s: errorcode %d", pbHost.Name, retcode)
	}

	cmd = fmt.Sprintf("sudo -u cladm -i kubectl delete node %s", pbHost.Name)
	retcode, _, _, err = clientSSH.Run(selectedMaster, cmd, outputs.COLLECT, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fmt.Errorf("error removing k8s node %s: errorcode %d", pbHost.Name, retcode)
	}

	// check node no longer belongs to k8s
	cmd = fmt.Sprintf("sudo -u cladm -i kubectl get node --selector='!node-role.kubernetes.io/master' | tail -n +2")
	retcode, retout, _, err = clientSSH.Run(selectedMaster, cmd, outputs.COLLECT, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fmt.Errorf("error listing k8s nodes %s: errorcode %d", pbHost.Name, retcode)
	}
	if strings.Contains(retout, pbHost.Name) {
		return fmt.Errorf("unable to remove k8s node '%s'", pbHost.Name)
	}

	return nil
}
