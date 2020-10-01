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

package dcos

import (
	"bytes"
	"fmt"
	"sync/atomic"
	txttmpl "text/template"

	rice "github.com/GeertJohan/go.rice"
	"github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/server/cluster/control"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/clusterstate"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/complexity"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/nodetype"
	"github.com/CS-SI/SafeScale/lib/server/cluster/flavors/dcos/enums/errorcode"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/template"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

//go:generate rice embed-go

const (
	bootstrapHTTPPort = 10080

	centos = "CentOS 7.3"
)

var (
	// templateBox is the rice box to use in this package
	templateBox atomic.Value

	// globalSystemRequirementsContent contains the script to install/configure Core features
	globalSystemRequirementsContent atomic.Value

	// funcMap defines the custom functions to be used in templates
	funcMap = txttmpl.FuncMap{
		"errcode": func(msg string) int {
			if code, ok := errorcode.StringMap[msg]; ok {
				return int(code)
			}
			return 1023
		},
	}

	// Makers initializes the control.Makers struct to construct a DCOS cluster
	Makers = control.Makers{
		MinimumRequiredServers:      minimumRequiredServers,
		DefaultGatewaySizing:        gatewaySizing,
		DefaultMasterSizing:         masterSizing,
		DefaultNodeSizing:           nodeSizing,
		DefaultImage:                defaultImage,
		ConfigureGateway:            configureGateway,
		ConfigureMaster:             configureMaster,
		ConfigureNode:               configureNode,
		GetTemplateBox:              getTemplateBox,
		GetGlobalSystemRequirements: getGlobalSystemRequirements,
		GetNodeInstallationScript:   getNodeInstallationScript,
		GetState:                    getState,
	}
)

func minimumRequiredServers(task concurrency.Task, foreman control.Foreman) (int, int, int) {
	masterCount := 0
	privateNodeCount := 0

	switch foreman.Cluster().GetIdentity(task).Complexity {
	case complexity.Small:
		masterCount = 1
		privateNodeCount = 2
	case complexity.Normal:
		masterCount = 3
		privateNodeCount = 4
	case complexity.Large:
		masterCount = 5
		privateNodeCount = 6
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
			MinRamSize:  15.0,
			MaxRamSize:  32.0,
			MinDiskSize: 80,
			GpuCount:    -1,
		},
	}
}

func nodeSizing(task concurrency.Task, foreman control.Foreman) *pb.HostDefinition {
	return &pb.HostDefinition{
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
	return centos
}

func configureMaster(task concurrency.Task, foreman control.Foreman, index int, host *pb.Host) error {
	box, err := getTemplateBox()
	if err != nil {
		return err
	}

	hostLabel := fmt.Sprintf("master #%d (%s)", index, host.Name)

	netCfg, err := foreman.Cluster().GetNetworkConfig(task)
	if err != nil {
		return err
	}
	retcode, _, _, err := foreman.ExecuteScript(
		box, funcMap, "dcos_configure_master.sh", map[string]interface{}{
			"BootstrapIP":   netCfg.GatewayIP,
			"BootstrapPort": bootstrapHTTPPort,
		}, host.Id,
	)
	if err != nil {
		logrus.Debugf("[%s] failed to remotely run configuration script: %s", hostLabel, err.Error())
		return err
	}
	if retcode != 0 {
		if retcode < int(errorcode.NextErrorCode) {
			errcode := errorcode.Enum(retcode)
			logrus.Debugf("[%s] configuration failed:\nretcode:%d (%s)", hostLabel, errcode, errcode.String())
			return fmt.Errorf("scripted Master configuration failed with error code %d (%s)", errcode, errcode.String())
		}

		logrus.Debugf("[%s] configuration failed:\nretcode=%d", hostLabel, retcode)
		return fmt.Errorf("scripted Master configuration failed with error code %d", retcode)
	}
	return nil
}

func configureNode(task concurrency.Task, foreman control.Foreman, index int, host *pb.Host) error {

	hostLabel := fmt.Sprintf("node #%d (%s)", index, host.Name)

	box, err := getTemplateBox()
	if err != nil {
		return err
	}
	netCfg, err := foreman.Cluster().GetNetworkConfig(task)
	if err != nil {
		return err
	}
	retcode, _, _, err := foreman.ExecuteScript(
		box, funcMap, "dcos_configure_node.sh", map[string]interface{}{
			"BootstrapIP":   netCfg.GatewayIP,
			"BootstrapPort": bootstrapHTTPPort,
		}, host.Id,
	)
	if err != nil {
		logrus.Debugf("[%s] failed to remotely run configuration script: %s\n", hostLabel, err.Error())
		return err
	}
	if retcode != 0 {
		if retcode < int(errorcode.NextErrorCode) {
			errcode := errorcode.Enum(retcode)
			logrus.Debugf("[%s] configuration failed: retcode: %d (%s)", hostLabel, errcode, errcode.String())
			return fmt.Errorf("scripted Agent configuration failed with error code %d (%s)", errcode, errcode.String())
		}
		logrus.Debugf("[%s] configuration failed: retcode=%d", hostLabel, retcode)
		return fmt.Errorf("scripted Agent configuration failed with error code '%d'", retcode)
	}

	return nil
}

func getNodeInstallationScript(task concurrency.Task, foreman control.Foreman, hostType nodetype.Enum) (string, map[string]interface{}) {
	data := map[string]interface{}{}

	var script string
	switch hostType {
	case nodetype.Master:
		script = "dcos_install_master.sh"
	case nodetype.Gateway, nodetype.Node:
		script = "dcos_install_node.sh"
	}
	return script, data
}

func configureGateway(task concurrency.Task, foreman control.Foreman) error {
	globalSystemRequirements, err := getGlobalSystemRequirements(task, foreman)
	if err != nil {
		return err
	}
	box, err := getTemplateBox()
	if err != nil {
		return err
	}

	var dnsServers []string
	cluster := foreman.Cluster()
	cfg, err := cluster.GetService(task).GetConfigurationOptions()
	if err == nil {
		dnsServers = cfg.GetSliceOfStrings("DNSList")
	}

	netCfg, err := cluster.GetNetworkConfig(task)
	if err != nil {
		return err
	}

	identity := cluster.GetIdentity(task)
	// VPL: FIXME: use property.NetworkV2 with VIP awareness...
	data := map[string]interface{}{
		"reserved_CommonRequirements": globalSystemRequirements,
		// "BootstrapIP":                 netCfg.PrimaryGatewayPrivateIP,
		"BootstrapIP":      netCfg.GatewayIP,
		"BootstrapPort":    bootstrapHTTPPort,
		"ClusterName":      identity.Name,
		"ClusterMasterIPs": cluster.ListMasterIPs(task),
		"DNSServerIPs":     dnsServers,
		"DefaultRouteIP":   netCfg.DefaultRouteIP,
		"SSHPrivateKey":    identity.Keypair.PrivateKey,
		"SSHPublicKey":     identity.Keypair.PublicKey,
	}
	retcode, _, _, err := foreman.ExecuteScript(box, funcMap, "dcos_prepare_bootstrap.sh", data, netCfg.GatewayID)
	if err != nil {
		logrus.Errorf("[gateway] configuration failed: %s", err.Error())
		return err
	}
	if retcode != 0 {
		if retcode < int(errorcode.NextErrorCode) {
			errcode := errorcode.Enum(retcode)
			logrus.Errorf("[gateway] configuration failed:\nretcode=%d (%s)", errcode, errcode.String())
			return fmt.Errorf(
				"scripted gateway configuration failed with error code %d (%s)", errcode, errcode.String(),
			)
		}

		logrus.Errorf("[gateway] configuration failed:\nretcode=%d", retcode)
		return fmt.Errorf("scripted gateway configuration failed with error code %d", retcode)
	}

	return nil
}

func getTemplateBox() (*rice.Box, error) {
	anon := templateBox.Load()
	if anon == nil {
		// Note: path MUST be literal for rice to work
		b, err := rice.FindBox("../dcos/scripts")
		if err != nil {
			return nil, err
		}
		templateBox.Store(b)
		anon = templateBox.Load()
	}
	return anon.(*rice.Box), nil
}

// getGlobalSystemRequirements returns the string corresponding to the script dcos_install_requirements.sh
// which installs common features (docker in particular)
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
		tmplString, err := box.String("dcos_install_requirements.sh")
		if err != nil {
			return "", fmt.Errorf("error loading script template: %s", err.Error())
		}

		// parse then execute the template
		// tmplPrepared, err := txttmpl.New("install_requirements").Funcs(template.MergeFuncs(funcMap, false)).Parse(tmplString)
		tmplPrepared, err := template.Parse("install_requirements", tmplString, funcMap)
		if err != nil {
			return "", fmt.Errorf("error parsing script template: %s", err.Error())
		}
		dataBuffer := bytes.NewBufferString("")
		identity := cluster.GetIdentity(task)
		err = tmplPrepared.Execute(
			dataBuffer, map[string]interface{}{
				"CIDR":                 netCfg.CIDR,
				"ClusterAdminUsername": "cladm",
				"ClusterAdminPassword": identity.AdminPassword,
				"SSHPublicKey":         identity.Keypair.PublicKey,
				"SSHPrivateKey":        identity.Keypair.PrivateKey,
			},
		)
		if err != nil {
			return "", fmt.Errorf("error realizing script template: %s", err.Error())
		}
		globalSystemRequirementsContent.Store(dataBuffer.String())
		anon = globalSystemRequirementsContent.Load()
	}
	return anon.(string), nil
}

// getState returns the current state of the cluster
// This method will trigger a effective state collection at each call
func getState(task concurrency.Task, foreman control.Foreman) (clusterstate.Enum, error) {
	var (
		retcode int
		ran     bool // Tells if command has been run on remote host
		stderr  string
	)

	cmd := "/opt/mesosphere/bin/dcos-diagnostics --diag"
	safescaleClt := client.New()
	safescaleCltHost := safescaleClt.Host
	masterID, err := foreman.Cluster().FindAvailableMaster(task)
	if err != nil {
		return clusterstate.Unknown, err
	}
	sshCfg, err := safescaleCltHost.SSHConfig(masterID)
	if err != nil {
		logrus.Errorf("failed to get ssh config to connect to master '%s': %s", masterID, err.Error())
		return clusterstate.Error, err

	}
	_, err = sshCfg.WaitServerReady("ready", temporal.GetContextTimeout())
	if err != nil {
		return clusterstate.Error, err
	}
	retcode, _, stderr, err = safescaleClt.SSH.Run(
		masterID, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout(),
	)
	if err != nil {
		logrus.Errorf("failed to run remote command to get cluster state: %v\n%s", err, stderr)
		return clusterstate.Error, err
	}
	ran = true

	if ran && retcode == 0 {
		return clusterstate.Nominal, nil
	}
	return clusterstate.Error, err
}
