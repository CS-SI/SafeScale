package install

import (
	"fmt"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/broker/client"

	clusterapi "github.com/CS-SI/SafeScale/deploy/cluster/api"
	"github.com/CS-SI/SafeScale/deploy/install/api"
)

// genericPackager is an object implementing the OS package management
// It handles package management on single host or entire cluster
type genericPackager struct {
	name      string
	checkCmd  string
	addCmd    string
	removeCmd string
}

// GetName returns the name of the installer (ex: apt, yum, dnf)
func (g *genericPackager) GetName() string {
	return g.name
}

// Check checks if the component is installed
func (g *genericPackager) Check(c api.Component, t api.Target) (bool, api.CheckResults, error) {
	var (
		onCluster     bool
		clusterTarget *ClusterTarget
	)

	hostTarget, ok := t.(*HostTarget)
	if !ok {
		clusterTarget, onCluster = t.(*ClusterTarget)
		if !onCluster {
			return false, api.CheckResults{}, fmt.Errorf("type of target is unknown")
		}
	}

	// First check if component is targeting host. Even in cluster context, host has to be targeteable
	specs := c.Specs()
	if specs.IsSet("component.targeting.host") {
		targeting := strings.ToLower(specs.GetString("component.targeting.host"))
		if targeting != "yes" && targeting != "true" {
			return false, api.CheckResults{}, fmt.Errorf("can't install, component doesn't target a host")
		}
	}

	rootKey := "component.installing." + g.name

	if onCluster {
		masterT, privnodeT, pubnodeT, err := validateClusterTargets(specs)
		if err != nil {
			return false, api.CheckResults{}, err
		}

		if !specs.IsSet(rootKey + ".uninstall") {
			msg := `syntax error in component '%s' specification file (%s):
					no key '%s.uninstall' found`
			return false, api.CheckResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename(), rootKey)
		}

		var (
			mastersChannel   chan map[string]api.CheckState
			pubNodesChannel  chan map[string]api.CheckState
			privNodesChannel chan map[string]api.CheckState
			cluster          = clusterTarget.cluster
			mastersStatus    = map[string]api.CheckState{}
			pubNodesStatus   = map[string]api.CheckState{}
			privNodesStatus  = map[string]api.CheckState{}
		)

		// Startig async jobs...
		if masterT != "0" {
			mastersChannel = make(chan map[string]api.CheckState)
			go asyncCheckHosts(cluster.ListMasterIDs(), c, mastersChannel)
		}
		if privnodeT != "0" {
			privNodesChannel = make(chan map[string]api.CheckState)
			go asyncCheckHosts(cluster.ListNodeIDs(false), c, privNodesChannel)
		}
		if pubnodeT != "0" {
			pubNodesChannel = make(chan map[string]api.CheckState)
			go asyncCheckHosts(cluster.ListNodeIDs(true), c, pubNodesChannel)
		}

		ok = true
		// Waiting async jobs
		if masterT != "0" {
			mastersStatus = <-mastersChannel
			for _, k := range mastersStatus {
				if !k.Success || !k.Present {
					ok = false
				}
			}
		}
		if privnodeT != "0" {
			privNodesStatus = <-privNodesChannel
			for _, k := range privNodesStatus {
				if !k.Success || !k.Present {
					ok = false
				}
			}
		}
		if pubnodeT != "0" {
			pubNodesStatus = <-pubNodesChannel
			for _, k := range pubNodesStatus {
				if !k.Success || !k.Present {
					ok = false
				}
			}
		}

		// Return the result
		return ok, api.CheckResults{
			Masters:      mastersStatus,
			PrivateNodes: privNodesStatus,
			PublicNodes:  pubNodesStatus,
		}, nil
	}

	// Single host mode
	if !specs.IsSet(rootKey + ".package") {
		msg := `syntax error in component '%s' specification file (yml):
				no key '%s.package' found`
		return false, api.CheckResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename(), rootKey)
	}
	packageName := specs.GetString(rootKey + ".package")
	if strings.TrimSpace(packageName) == "" {
		msg := `syntax error in component '%s' specification file (%s):
				key '%s.package' is empty`
		return false, api.CheckResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename(), rootKey)
	}

	cmdStr := fmt.Sprintf(g.checkCmd, packageName)
	retcode, _, _, err := client.New().Ssh.Run(hostTarget.host.ID, cmdStr, 0)
	if err != nil {
		return false, api.CheckResults{}, err
	}
	ok = retcode == 0
	return ok, api.CheckResults{
		PrivateNodes: map[string]api.CheckState{
			hostTarget.host.Name: api.CheckState{Success: true, Present: ok},
		},
	}, nil
}

// Add installs the component using apt
func (g *genericPackager) Add(c api.Component, t api.Target, v map[string]interface{}) (bool, api.AddResults, error) {
	var (
		onCluster     bool
		clusterTarget *ClusterTarget
	)

	hostTarget, ok := t.(*HostTarget)
	if !ok {
		clusterTarget, onCluster = t.(*ClusterTarget)
		if !onCluster {
			return false, api.AddResults{}, fmt.Errorf("type of target is unknown")
		}
	}

	// First check if component is targeting host. Even in cluster context, host has to be targateable
	specs := c.Specs()
	if specs.IsSet("component.targeting.host") {
		targeting := strings.ToLower(specs.GetString("component.targeting.host"))
		if targeting != "yes" && targeting != "true" {
			return false, api.AddResults{}, fmt.Errorf("can't install, component doesn't target a host")
		}
	}

	rootKey := "component.installing." + g.name

	if onCluster {
		// Cluster mode
		masterT, privnodeT, pubnodeT, err := validateClusterTargets(specs)
		if err != nil {
			return false, api.AddResults{}, err
		}

		if !specs.IsSet(rootKey + ".uninstall") {
			msg := `syntax error in component '%s' specification file (%s):
					no key '%s.uninstall' found`
			return false, api.AddResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename(), rootKey)
		}

		var (
			list             []string
			mastersChannel   chan map[string]error
			pubNodesChannel  chan map[string]error
			privNodesChannel chan map[string]error
			cluster          = clusterTarget.cluster
			mastersStatus    = map[string]error{}
			pubNodesStatus   = map[string]error{}
			privNodesStatus  = map[string]error{}
		)

		if masterT != "0" {
			if masterT != "0" {
				if masterT == "1" {
					hostID, err := cluster.FindAvailableMaster()
					if err != nil {
						return false, api.AddResults{}, err
					}
					list = append(list, hostID)
				} else {
					list = cluster.ListMasterIDs()
				}
			}
			mastersChannel = make(chan map[string]error)
			go asyncAddOnHosts(list, c, v, mastersChannel)
		}
		if privnodeT != "0" {
			if privnodeT == "1" {
				hostID, err := cluster.FindAvailableNode(false)
				if err != nil {
					return false, api.AddResults{}, err
				}
				list = []string{hostID}
			} else {
				list = cluster.ListNodeIDs(false)
			}
			privNodesChannel = make(chan map[string]error)
			go asyncAddOnHosts(list, c, v, privNodesChannel)
		}
		if pubnodeT != "0" {
			if pubnodeT == "1" {
				hostID, err := cluster.FindAvailableNode(true)
				if err != nil {
					return false, api.AddResults{}, err
				}
				list = []string{hostID}
			} else {
				list = cluster.ListNodeIDs(true)
			}
			pubNodesChannel = make(chan map[string]error)
			go asyncAddOnHosts(list, c, v, pubNodesChannel)
		}

		ok = true

		// Waiting go routines...
		if masterT != "0" {
			mastersStatus = <-mastersChannel
			for _, k := range mastersStatus {
				if k != nil {
					ok = false
					break
				}
			}
		}
		if privnodeT != "0" {
			privNodesStatus = <-privNodesChannel
			for _, k := range privNodesStatus {
				if k != nil {
					ok = false
					break
				}
			}
		}
		if pubnodeT != "0" {
			pubNodesStatus = <-pubNodesChannel
			for _, k := range pubNodesStatus {
				if k != nil {
					ok = false
					break
				}
			}
		}

		// Return the result
		return ok, api.AddResults{
			Masters:      mastersStatus,
			PrivateNodes: privNodesStatus,
			PublicNodes:  pubNodesStatus,
		}, nil
	}

	// Host target
	if !specs.IsSet(rootKey + ".package") {
		msg := `syntax error in component '%s' specification file (%s):
		        no key '%s.package' found`
		return false, api.AddResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename(), rootKey)
	}
	packageName := specs.GetString(rootKey + ".package")
	if strings.TrimSpace(packageName) == "" {
		msg := `syntax error in component '%s' specification file (%s):
		        key '%s.package' is empty`
		return false, api.AddResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename(), rootKey)
	}
	cmdStr := fmt.Sprintf(g.addCmd, packageName)
	duration := specs.GetInt(rootKey + ".estimated_execution_time")
	if duration == 0 {
		duration = 5
	}
	retcode, _, stderr, err := client.New().Ssh.Run(hostTarget.host.ID, cmdStr, time.Duration(duration)*time.Minute)
	if err != nil {
		return false, api.AddResults{}, err
	}
	var status error
	ok = retcode == 0
	if !ok {
		status = fmt.Errorf("install command failed for component '%s': %s", c.DisplayName(), stderr)
	}
	return ok, api.AddResults{
		PrivateNodes: map[string]error{
			hostTarget.host.Name: status,
		},
	}, nil
}

// Remove uninstalls the component using the RemoveScript script
func (g *genericPackager) Remove(c api.Component, t api.Target) (bool, api.RemoveResults, error) {
	var (
		onCluster     bool
		hostTarget    *HostTarget
		clusterTarget *ClusterTarget
		ok            bool
	)

	hostTarget, ok = t.(*HostTarget)
	if !ok {
		clusterTarget, onCluster = t.(*ClusterTarget)
		if !onCluster {
			return false, api.RemoveResults{}, fmt.Errorf("type of target is unknown")
		}
	}

	// First check if component is targeting host. Even in cluster context, host has to be targateable
	specs := c.Specs()
	if specs.IsSet("component.targeting.host") {
		targeting := strings.ToLower(specs.GetString("component.targeting.host"))
		if targeting != "yes" && targeting != "true" {
			return false, api.RemoveResults{}, fmt.Errorf("can't install, component doesn't target a host")
		}
	}

	rootKey := "component.installing." + g.name

	if onCluster {
		masterT, privnodeT, pubnodeT, err := validateClusterTargets(specs)
		if err != nil {
			return false, api.RemoveResults{}, err
		}

		if !specs.IsSet(rootKey + ".uninstall") {
			msg := `syntax error in component '%s' specification file (%s):
					no key '%s.uninstall' found`
			return false, api.RemoveResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename(), rootKey)
		}

		var (
			list             []string
			mastersChannel   chan map[string]error
			pubNodesChannel  chan map[string]error
			privNodesChannel chan map[string]error
		)
		cluster := clusterTarget.cluster
		mastersStatus := map[string]error{}
		pubNodesStatus := map[string]error{}
		privNodesStatus := map[string]error{}

		if masterT != "0" {
			if masterT != "0" {
				if masterT == "1" {
					hostID, err := findConcernedMaster(cluster, c)
					if err != nil {
						return false, api.RemoveResults{}, err
					}
					list = append(list, hostID)
				} else {
					list = cluster.ListMasterIDs()
				}
			}
			mastersChannel = make(chan map[string]error)
			go asyncRemoveFromHosts(list, c, mastersChannel)
		}
		if privnodeT != "0" {
			if privnodeT == "1" {
				hostID, err := findConcernedNode(cluster, c, false)
				if err != nil {
					return false, api.RemoveResults{}, err
				}
				list = []string{hostID}
			} else {
				list = cluster.ListNodeIDs(false)
			}
			privNodesChannel = make(chan map[string]error)
			go asyncRemoveFromHosts(list, c, privNodesChannel)
		}
		if pubnodeT != "0" {
			if pubnodeT == "1" {
				hostID, err := findConcernedNode(cluster, c, true)
				if err != nil {
					return false, api.RemoveResults{}, err
				}
				list = []string{hostID}
			} else {
				list = cluster.ListNodeIDs(true)
			}
			pubNodesChannel = make(chan map[string]error)
			go asyncRemoveFromHosts(list, c, pubNodesChannel)
		}

		ok = true

		// Waiting go routines...
		if masterT != "0" {
			mastersStatus = <-mastersChannel
			for _, k := range mastersStatus {
				if k != nil {
					ok = false
					break
				}
			}
		}
		if privnodeT != "0" {
			privNodesStatus = <-privNodesChannel
			for _, k := range privNodesStatus {
				if k != nil {
					ok = false
					break
				}
			}
		}
		if pubnodeT != "0" {
			pubNodesStatus = <-pubNodesChannel
			for _, k := range pubNodesStatus {
				if k != nil {
					ok = false
					break
				}
			}
		}

		// Return the result
		return ok, api.RemoveResults{
			AddResults: api.AddResults{
				Masters:      mastersStatus,
				PrivateNodes: privNodesStatus,
				PublicNodes:  pubNodesStatus,
			},
		}, nil
	}

	// Single host mode
	if !specs.IsSet(rootKey + ".package") {
		msg := `syntax error in component '%s' specification file (%s):
				no key '%s.package' found`
		return false, api.RemoveResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename(), rootKey)
	}
	packageName := specs.GetString(rootKey + ".package")
	if strings.TrimSpace(packageName) == "" {
		msg := `syntax error in component '%s' specification file (%s):
				key '%s.package' is empty`
		return false, api.RemoveResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename(), rootKey)
	}
	cmdStr := fmt.Sprintf(g.removeCmd, packageName)
	duration := specs.GetInt(rootKey + ".estimated_execution_time")
	if duration == 0 {
		duration = 5
	}
	retcode, _, _, err := client.New().Ssh.Run(hostTarget.host.ID, cmdStr, time.Duration(duration)*time.Minute)
	if err != nil {
		return false, api.RemoveResults{}, err
	}
	var status error
	ok = retcode == 0
	if !ok {
		status = fmt.Errorf("uninstall command failed for component '%s'", c.DisplayName())
	}
	return ok, api.RemoveResults{
		AddResults: api.AddResults{
			PrivateNodes: map[string]error{
				hostTarget.host.Name: status,
			},
		},
	}, nil
}

// findConcernedMaster determines from all masters which one has the component installed
func findConcernedMaster(cluster clusterapi.ClusterAPI, c api.Component) (string, error) {
	// metadata not yet implemented for components, so assuming the concerned master is
	// the available one
	return cluster.FindAvailableMaster()
	//for _, m := range cluster.ListMasterIDs() {
	//}
}

// findConcernedNode determines from all nodes which one has the component installed
func findConcernedNode(cluster clusterapi.ClusterAPI, c api.Component, public bool) (string, error) {
	// metadata not yet implemented for components, so assuming the concerned node is
	// the first one
	list := cluster.ListNodeIDs(public)
	if len(list) > 0 {
		return list[0], nil
	}
	return "", fmt.Errorf("no node found")
	//for _, m := range cluster.ListNodeIDs(public) {
	//}
}

// aptInstaller is an installer using script to add and remove a component
type aptInstaller struct {
	genericPackager
}

// NewAptInstaller creates a new instance of Installer using script
func NewAptInstaller() api.Installer {
	return &aptInstaller{
		genericPackager: genericPackager{
			name:      "apt",
			checkCmd:  "sudo dpkg-query -s '%s' &>/dev/null",
			addCmd:    "sudo apt-get update -y; sudo apt-get install -y '%s'",
			removeCmd: "sudo apt-get remove -y '%s'",
		},
	}
}

// yumInstaller is an installer using yum to add and remove a component
type yumInstaller struct {
	genericPackager
}

// NewYumInstaller creates a new instance of Installer using script
func NewYumInstaller() api.Installer {
	return &yumInstaller{
		genericPackager: genericPackager{
			name:      "yum",
			checkCmd:  "sudo rpm -q %s &>/dev/null",
			addCmd:    "sudo yum makecache fast; sudo yum install -y %s",
			removeCmd: "sudo yum remove -y %s",
		},
	}
}

// dnfInstaller is an installer using yum to add and remove a component
type dnfInstaller struct {
	genericPackager
}

// NewDnfInstaller creates a new instance of Installer using script
func NewDnfInstaller() api.Installer {
	return &dnfInstaller{
		genericPackager: genericPackager{
			name:      "dnf",
			checkCmd:  "sudo dnf list installed %s &>/dev/null",
			addCmd:    "sudo dnf install -y %s",
			removeCmd: "sudo dnf uninstall -y %s",
		},
	}
}
