/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

	rice "github.com/GeertJohan/go.rice"
	"github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/server/cluster/control"
	clusterpropsv1 "github.com/CS-SI/SafeScale/lib/server/cluster/control/properties/v1"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/complexity"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/nodetype"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/property"
	"github.com/CS-SI/SafeScale/lib/server/install"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/template"
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
		UnconfigureCluster:          unconfigureCluster,
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
	cluster := foreman.Cluster().(*control.Controller)
	identity := cluster.GetIdentity(task)
	clusterName := identity.Name
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
	_, ok := req.DisabledDefaultFeatures["hardening"]
	v["Hardening"] = strconv.FormatBool(!ok)

	// If cluster complexity is not small or cloud provider provides support for VIP, creates such a VIP if not already done
	var controlPlaneV1 *clusterpropsv1.ControlPlane
	svc := cluster.GetService(task)
	if identity.Complexity != complexity.Small && cluster.GetService(task).GetCapabilities().PrivateVirtualIP {
		err = cluster.GetProperties(task).LockForWrite(property.ControlPlaneV1).ThenUse(func(clonable data.Clonable) error {
			controlPlaneV1 = clonable.(*clusterpropsv1.ControlPlane)
			return nil
		})
		if err != nil {
			return err
		}

		if controlPlaneV1.VirtualIP == nil {
			netCfg, err := cluster.GetNetworkConfig(task)
			if err != nil {
				return err
			}

			vip, err := svc.CreateVIP(netCfg.NetworkID, clusterName+"-ControlPlaneVIP")
			if err != nil {
				return err
			}
			defer func() {
				if err != nil {
					derr := svc.DeleteVIP(vip)
					if derr != nil {
						logrus.Errorf("Cleaning up on failure, failed to delete VirtualIP: %v", derr)
					}
				}
			}()

			for _, id := range cluster.ListMasterIDs(task) {
				err = svc.BindHostToVIP(vip, id)
				if err != nil {
					return err
				}
				defer func(i string) {
					if err != nil {
						derr := svc.UnbindHostFromVIP(vip, i)
						if derr != nil {
							logrus.Errorf("Cleaning up on failure, failed to delete VirtualIP: %v", derr)
						}
					}
				}(id)
			}

			err = cluster.UpdateMetadata(task, func() error {
				return cluster.GetProperties(task).LockForWrite(property.ControlPlaneV1).ThenUse(func(clonable data.Clonable) error {
					controlPlaneV1 = clonable.(*clusterpropsv1.ControlPlane)
					controlPlaneV1.VirtualIP = vip
					controlPlaneV1.VirtualIP.Hosts = cluster.ListMasterIDs(task)
					return nil
				})
			})
			if err != nil {
				return err
			}
		}
	}

	// Disable dashboard if requested
	_, ok = req.DisabledDefaultFeatures["dashboard"]
	v["Dashboard"] = strconv.FormatBool(!ok)

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

	// If helm is not disabled, installs it
	if _, ok = req.DisabledDefaultFeatures["helm"]; !ok {
		logrus.Println(fmt.Sprintf("[cluster %s] adding feature 'k8s.helm2'...", clusterName))

		feature, err = install.NewFeature(task, "k8s.helm2")
		if err != nil {
			logrus.Errorf("[cluster %s] failed to instantiate feature 'k8s.helm2': %v", clusterName, err)
			return fmt.Errorf("failed to prepare feature 'k8s.helm2': %s", err.Error())
		}

		// Installs kubernetes feature
		results, err = feature.Add(target, install.Variables{}, install.Settings{})
		if err != nil {
			logrus.Errorf("[cluster %s] failed to add feature 'k8s.helm2': %s", clusterName, err.Error())
			return err
		}
		if !results.Successful() {
			err = fmt.Errorf(results.AllErrorMessages())
			logrus.Errorf("[cluster %s] failed to add feature 'k8s.helm2': %s", clusterName, err.Error())
			return err
		}
		logrus.Println(fmt.Sprintf("[cluster %s] feature 'k8s.helm2' addition successful.", clusterName))
	}

	return nil
}

func unconfigureCluster(task concurrency.Task, foreman control.Foreman) error {
	clusterName := foreman.Cluster().GetIdentity(task).Name
	logrus.Println(fmt.Sprintf("[cluster %s] removing control plane virtual IP...", clusterName))

	err := foreman.Cluster().GetProperties(task).LockForWrite(property.ControlPlaneV1).ThenUse(func(clonable data.Clonable) error {
		controlPlaneV1, ok := clonable.(*clusterpropsv1.ControlPlane)
		if !ok {
			return scerr.InconsistentError("property ControlPlaneV1 doesn't contain valid data")
		}
		if controlPlaneV1.VirtualIP != nil {
			inErr := foreman.Cluster().GetService(task).DeleteVIP(controlPlaneV1.VirtualIP)
			if inErr != nil {
				return inErr
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func getNodeInstallationScript(task concurrency.Task, foreman control.Foreman, nodeType nodetype.Enum) (string, map[string]interface{}) {
	script := ""
	theData := map[string]interface{}{}

	switch nodeType {
	case nodetype.Master:
		script = "k8s_install_master.sh"
	case nodetype.Node, nodetype.Gateway:
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
		// tmplPrepared, err := txttmpl.New("install_requirements").Funcs(template.MergeFuncs(nil, false)).Parse(tmplString)
		tmplPrepared, err := template.Parse("install_requirements", tmplString, nil)
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
