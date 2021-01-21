/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

package flavors

import (
	"bytes"
	"sync/atomic"

	rice "github.com/GeertJohan/go.rice"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/template"
)

var (
	templateBox atomic.Value
)

// Makers ...
type Makers struct {
	MinimumRequiredServers func(task concurrency.Task, c resources.Cluster) (uint, uint, uint, fail.Error)  // returns masterCount, privateNodeCount, publicNodeCount
	DefaultGatewaySizing   func(task concurrency.Task, c resources.Cluster) abstract.HostSizingRequirements // sizing of gateway(s)
	DefaultMasterSizing    func(task concurrency.Task, c resources.Cluster) abstract.HostSizingRequirements // default sizing of master(s)
	DefaultNodeSizing      func(task concurrency.Task, c resources.Cluster) abstract.HostSizingRequirements // default sizing of node(s)
	DefaultImage           func(task concurrency.Task, c resources.Cluster) string                          // default image of server(s)
	// GetNodeInstallationScript func(task concurrency.Task, c resources.Cluster, nodeType clusternodetype.Enum) (string, data.Map)
	// GetGlobalSystemRequirements func(task concurrency.Task, c resources.Cluster) (string, fail.Error)
	// GetTemplateBox         func() (*rice.Box, fail.Error)
	ConfigureGateway       func(task concurrency.Task, c resources.Cluster) fail.Error
	CreateMaster           func(task concurrency.Task, c resources.Cluster, index uint) fail.Error
	ConfigureMaster        func(task concurrency.Task, c resources.Cluster, index uint, host resources.Host) fail.Error
	UnconfigureMaster      func(task concurrency.Task, c resources.Cluster, host resources.Host) fail.Error
	CreateNode             func(task concurrency.Task, c resources.Cluster, index uint, host resources.Host) fail.Error
	ConfigureNode          func(task concurrency.Task, c resources.Cluster, index uint, host resources.Host) fail.Error
	UnconfigureNode        func(task concurrency.Task, c resources.Cluster, host resources.Host, selectedMaster resources.Host) fail.Error
	ConfigureCluster       func(task concurrency.Task, c resources.Cluster) fail.Error
	UnconfigureCluster     func(task concurrency.Task, c resources.Cluster) fail.Error
	JoinMasterToCluster    func(task concurrency.Task, c resources.Cluster, host resources.Host) fail.Error
	JoinNodeToCluster      func(task concurrency.Task, c resources.Cluster, host resources.Host) fail.Error
	LeaveMasterFromCluster func(task concurrency.Task, c resources.Cluster, host resources.Host) fail.Error
	LeaveNodeFromCluster   func(task concurrency.Task, c resources.Cluster, host resources.Host, selectedMaster resources.Host) fail.Error
	GetState               func(task concurrency.Task, c resources.Cluster) (clusterstate.Enum, fail.Error)
}

func getTemplateBox() (*rice.Box, fail.Error) {
	anon := templateBox.Load()
	if anon == nil {
		// Note: path MUST be literal for rice to work
		b, err := rice.FindBox("../clusterflavors/scripts")
		if err != nil {
			return nil, fail.ToError(err)
		}
		templateBox.Store(b)
		anon = templateBox.Load()
	}
	return anon.(*rice.Box), nil
}

func GetGlobalSystemRequirements(task concurrency.Task, c resources.Cluster) (string, fail.Error) {
	// find the rice.Box
	box, xerr := getTemplateBox()
	if xerr != nil {
		return "", xerr
	}

	// We will need information from cluster network
	netCfg, xerr := c.GetNetworkConfig(task)
	if xerr != nil {
		return "", xerr
	}

	identity, xerr := c.GetIdentity(task)
	if xerr != nil {
		return "", xerr
	}

	// get file contents as string
	tmplString, err := box.String("node_install_requirements.sh")
	if err != nil {
		return "", fail.Wrap(err, "error loading script template")
	}

	// parse then execute the template
	tmplPrepared, err := template.Parse("node_install_requirements", tmplString)
	if err != nil {
		return "", fail.Wrap(err, "error parsing script template")
	}
	dataBuffer := bytes.NewBufferString("")
	err = tmplPrepared.Execute(dataBuffer, map[string]interface{}{
		"IPRanges":             netCfg.CIDR,
		"ClusterAdminUsername": "cladm",
		"ClusterAdminPassword": identity.AdminPassword,
		"SSHPublicKey":         identity.Keypair.PublicKey,
		"SSHPrivateKey":        identity.Keypair.PrivateKey,
	})
	if err != nil {
		return "", fail.Wrap(err, "error realizing script template")
	}

	return dataBuffer.String(), nil
}
