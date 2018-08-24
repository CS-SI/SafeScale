package install

import (
	"fmt"
	"strings"
	"time"

	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/broker/client"

	clusterapi "github.com/CS-SI/SafeScale/deploy/cluster/api"
	"github.com/CS-SI/SafeScale/deploy/install/api"
)

const (
	componentScriptTemplateContent = `
rm -f /var/tmp/{{.reserved_Name}}.component.{{.reserved_Action}}.log
exec 1<&-
exec 2<&-
exec 1<>/var/tmp/{{.reserved_Name}}.component.{{.reserved_Action}}.log
exec 2>&1

{{ .reserved_CommonTools }}

{{ .reserved_Content }}
`
)

// scriptInstaller is an installer using script to add and remove a component
type scriptInstaller struct{}

func (i *scriptInstaller) GetName() string {
	return "script"
}

func determineContext(t api.Target) (hT *HostTarget, cT *ClusterTarget, nT *NodeTarget) {
	hT = nil
	cT = nil
	nT = nil

	var ok bool

	hT, ok = t.(*HostTarget)
	if !ok {
		cT, ok = t.(*ClusterTarget)
		if !ok {
			nT, ok = t.(*NodeTarget)
		}
	}
	return
}

// Check checks if the component is installed, using the check script in Specs
func (i *scriptInstaller) Check(c api.Component, t api.Target) (bool, api.CheckResults, error) {
	specs := c.Specs()
	if !specs.IsSet("component.installing.script.check") {
		msg := `syntax error in component '%s' specification file (%s):
				no key 'component.installing.script.check' found`
		return false, api.CheckResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}

	hostTarget, clusterTarget, nodeTarget := determineContext(t)

	// Host target
	if hostTarget != nil {
		if specs.IsSet("component.targeting.host") {
			targeting := strings.ToLower(specs.GetString("component.targeting.host"))
			if targeting != "yes" && targeting != "true" {
				return false, api.CheckResults{}, fmt.Errorf("can't check, component doesn't target a host")
			}
		}
		return i.checkOnHost(c, hostTarget.host)
	}
	// Cluster target
	if clusterTarget != nil {
		return i.checkOnCluster(c, clusterTarget.cluster)
	}
	// Node target (== Host Target without verifying if the component is targetting a host)
	if nodeTarget != nil {
		return i.checkOnHost(c, nodeTarget.host)
	}

	return false, api.CheckResults{}, fmt.Errorf("type of target is unknown")
}

func (i *scriptInstaller) checkOnHost(
	c api.Component, host *pb.Host,
) (bool, api.CheckResults, error) {
	specs := c.Specs()
	checkScript := specs.GetString("component.installing.script.check")
	if strings.TrimSpace(checkScript) == "" {
		msg := `syntax error in component '%s' specification file (%s):
				key 'component.installing.script.check' is empty`
		return false, api.CheckResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}
	cmdStr, err := realizeScript(map[string]interface{}{
		"reserved_Name":    c.BaseFilename(),
		"reserved_Content": checkScript,
		"reserved_Action":  "check",
	})
	if err != nil {
		return false, api.CheckResults{}, err
	}
	filename := fmt.Sprintf("/var/tmp/%s_check.sh", c.BaseFilename())
	err = uploadStringToTargetFile(cmdStr, host, filename)
	if err != nil {
		return false, api.CheckResults{}, err
	}
	cmd := fmt.Sprintf("sudo bash %s ; rc=$?; sudo rm -f %s; exit $rc", filename, filename)
	retcode, _, _, err := client.New().Ssh.Run(host.ID, cmd, 0)
	if err != nil {
		return false, api.CheckResults{}, err
	}
	ok := retcode == 0
	return ok, api.CheckResults{
		PrivateNodes: map[string]api.CheckState{
			host.Name: api.CheckState{Success: true, Present: ok},
		},
	}, nil
}

func (i *scriptInstaller) checkOnCluster(c api.Component, cluster clusterapi.ClusterAPI) (bool, api.CheckResults, error) {
	specs := c.Specs()
	masterT, privnodeT, pubnodeT, err := validateClusterTargets(specs)
	if err != nil {
		return false, api.CheckResults{}, err
	}

	var (
		mastersChannel   chan map[string]api.CheckState
		privnodesChannel chan map[string]api.CheckState
		pubnodesChannel  chan map[string]api.CheckState
		mastersStatus    = map[string]api.CheckState{}
		privnodesStatus  = map[string]api.CheckState{}
		pubnodesStatus   = map[string]api.CheckState{}
		checked          int
	)

	if masterT != "0" {
		mastersChannel = make(chan map[string]api.CheckState)
		list := cluster.ListMasterIDs()
		checked += len(list)
		go asyncCheckHosts(list, c, mastersChannel)
	}
	if privnodeT != "0" {
		privnodesChannel = make(chan map[string]api.CheckState)
		list := cluster.ListNodeIDs(false)
		checked += len(list)
		go asyncCheckHosts(list, c, privnodesChannel)
	}
	if pubnodeT != "0" {
		pubnodesChannel = make(chan map[string]api.CheckState)
		list := cluster.ListNodeIDs(true)
		checked += len(list)
		go asyncCheckHosts(list, c, pubnodesChannel)
	}

	ok := true
	if masterT != "0" {
		mastersStatus = <-mastersChannel
		for _, k := range mastersStatus {
			if !k.Success || !k.Present {
				ok = false
				break
			}
		}
	}
	if privnodeT != "0" {
		privnodesStatus = <-privnodesChannel
		for _, k := range privnodesStatus {
			if !k.Success || !k.Present {
				ok = false
				break
			}
		}
	}
	if pubnodeT != "0" {
		pubnodesStatus = <-pubnodesChannel
		for _, k := range pubnodesStatus {
			if !k.Success || !k.Present {
				ok = false
				break
			}
		}
	}
	// If no hosts have been selected to check state, don't say it's installed
	if checked <= 0 {
		return false, api.CheckResults{}, fmt.Errorf("no hosts selected to be checked")
	}
	return ok, api.CheckResults{
		Masters:      mastersStatus,
		PrivateNodes: privnodesStatus,
		PublicNodes:  pubnodesStatus,
	}, nil
}

// Add installs the component using the install script in Specs
// 'values' contains the values associated with parameters as defined in specification file
func (i *scriptInstaller) Add(c api.Component, t api.Target, v map[string]interface{}) (bool, api.AddResults, error) {
	specs := c.Specs()
	// If component is installed, do nothing but responds with success
	ok, _, err := i.Check(c, t)
	if err != nil {
		return false, api.AddResults{}, err
	}
	if ok {
		fmt.Printf("Component '%s' is already installed.", c.DisplayName())
		return true, api.AddResults{}, nil
	}

	// Installs first dependencies if there is any
	err = installRequirements(specs, t, v)
	if err != nil {
		return false, api.AddResults{}, err
	}

	// Determining if install script is defined in specification file
	if !specs.IsSet("component.installing.script.install") {
		msg := `syntax error in component '%s' specification file (%s):
				no key 'component.installing.script.install' found`
		return false, api.AddResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}

	hostTarget, clusterTarget, nodeTarget := determineContext(t)

	if hostTarget != nil {
		if specs.IsSet("component.targeting.host") {
			targeting := strings.ToLower(specs.GetString("component.targeting.host"))
			if targeting != "yes" && targeting != "true" {
				return false, api.AddResults{}, fmt.Errorf("can't install, component doesn't target a host")
			}
		}
		return i.addOnHost(c, hostTarget.host, v)
	}
	if clusterTarget != nil {
		return i.addOnCluster(c, clusterTarget.cluster, v)
	}
	if nodeTarget != nil {
		return i.addOnHost(c, nodeTarget.host, v)
	}

	return false, api.AddResults{}, fmt.Errorf("type of target is unknown")
}

// addOnHost installs a component on an host
func (i *scriptInstaller) addOnHost(
	c api.Component, host *pb.Host, v map[string]interface{},
) (bool, api.AddResults, error) {

	specs := c.Specs()
	addScript := specs.GetString("component.installing.script.install")
	if strings.TrimSpace(addScript) == "" {
		msg := `syntax error in component '%s' specification file (%s):
				key 'component.installing.script.install' is empty`
		return false, api.AddResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}
	v["reserved_Name"] = c.BaseFilename()
	v["reserved_Content"] = addScript
	v["reserved_Action"] = "install"
	cmdStr, err := realizeScript(v)
	if err != nil {
		return false, api.AddResults{}, err
	}
	filename := fmt.Sprintf("/var/tmp/%s_install.sh", c.BaseFilename())
	err = uploadStringToTargetFile(cmdStr, host, filename)
	if err != nil {
		return false, api.AddResults{}, err
	}
	var cmd string
	// if debug {
	if true {
		cmd = fmt.Sprintf("sudo bash %s; rc=$?; exit $rc", filename)
	} else {
		cmd = fmt.Sprintf("sudo bash %s; rc=$?; sudo rm -f %s; exit $rc", filename, filename)
	}
	duration := specs.GetInt("component.installing.script.estimated_execution_time")
	if duration == 0 {
		duration = 5
	}
	retcode, _, stderr, err := client.New().Ssh.Run(host.ID, cmd, time.Duration(duration)*time.Minute)
	if err != nil {
		return false, api.AddResults{}, err
	}
	var status error
	ok := retcode == 0
	if !ok {
		status = fmt.Errorf("install script for component '%s' failed, retcode=%d:\n%s", c.DisplayName(), retcode, stderr)
	}
	return ok, api.AddResults{
		PrivateNodes: map[string]error{
			host.Name: status,
		},
	}, nil

}

// addOnCluster installs a component on a cluster
func (i *scriptInstaller) addOnCluster(
	c api.Component, cluster clusterapi.ClusterAPI, v map[string]interface{},
) (bool, api.AddResults, error) {

	specs := c.Specs()
	masterT, privnodeT, pubnodeT, err := validateClusterTargets(specs)
	if err != nil {
		return false, api.AddResults{}, err
	}

	var (
		mastersChannel   chan map[string]error
		privnodesChannel chan map[string]error
		pubnodesChannel  chan map[string]error
		list             []string
		mastersStatus    = map[string]error{}
		privnodesStatus  = map[string]error{}
		pubnodesStatus   = map[string]error{}
		checked          int
	)

	v["MasterIDs"] = cluster.ListMasterIDs()
	v["MasterIPs"] = cluster.ListMasterIPs()
	//v["DomainName"] = cluster.GetConfig().DomainName

	if masterT != "0" {
		if masterT == "1" {
			hostID, err := cluster.FindAvailableMaster()
			if err != nil {
				return false, api.AddResults{}, err
			}
			list = []string{hostID}
		} else {
			list = cluster.ListMasterIDs()
		}
		mastersChannel = make(chan map[string]error)
		go asyncAddOnHosts(list, c, v, mastersChannel)
		checked += len(list)
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
		privnodesChannel = make(chan map[string]error)
		go asyncAddOnHosts(list, c, v, privnodesChannel)
		checked += len(list)
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
		pubnodesChannel = make(chan map[string]error)
		go asyncAddOnHosts(list, c, v, pubnodesChannel)
		checked += len(list)
	}

	ok := true
	if masterT != "0" {
		mastersStatus = <-mastersChannel
		for _, k := range mastersStatus {
			if k != nil {
				ok = false
				break
			}
		}
	}
	privnodesStatus = map[string]error{}
	if privnodeT != "0" {
		privnodesStatus = <-privnodesChannel
		for _, k := range privnodesStatus {
			if k != nil {
				ok = false
				break
			}
		}
	}
	pubnodesStatus = map[string]error{}
	if pubnodeT != "0" {
		pubnodesStatus = <-pubnodesChannel
		for _, k := range pubnodesStatus {
			if k != nil {
				ok = false
				break
			}
		}
	}
	if checked <= 0 {
		return false, api.AddResults{}, fmt.Errorf("no hosts selected to install on")
	}
	return ok, api.AddResults{
		Masters:      mastersStatus,
		PrivateNodes: privnodesStatus,
		PublicNodes:  pubnodesStatus,
	}, nil
}

// Remove uninstalls the component
func (i *scriptInstaller) Remove(c api.Component, t api.Target) (bool, api.RemoveResults, error) {

	specs := c.Specs()
	if !specs.IsSet("component.installing.script.uninstall") {
		msg := `syntax error in component '%s' specification file (%s):
				no key 'component.installing.script.uninstall' found`
		return false, api.RemoveResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}

	hostTarget, clusterTarget, nodeTarget := determineContext(t)

	if hostTarget != nil {
		if specs.IsSet("component.targeting.host") {
			targeting := strings.ToLower(specs.GetString("component.targeting.host"))
			if targeting != "yes" && targeting != "true" {
				return false, api.RemoveResults{}, fmt.Errorf("can't install, component doesn't target a host")
			}
		}
		return i.removeFromHost(c, hostTarget.host)
	}
	if clusterTarget != nil {
		return i.removeFromCluster(c, clusterTarget.cluster)
	}
	if nodeTarget != nil {
		return i.removeFromHost(c, hostTarget.host)
	}
	return false, api.RemoveResults{}, fmt.Errorf("type of target is unknown")
}

// removeFromHost uninstalls a component from a host
func (i *scriptInstaller) removeFromHost(c api.Component, host *pb.Host) (bool, api.RemoveResults, error) {
	specs := c.Specs()
	removeScript := specs.GetString("component.installing.script.uninstall")
	if strings.TrimSpace(removeScript) == "" {
		msg := `syntax error in component '%s' specification file (%s):
		        key 'component.installing.script.uninstall' is empty`
		return false, api.RemoveResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}
	cmdStr, err := realizeScript(map[string]interface{}{
		"reserved_Name":    c.BaseFilename(),
		"reserved_Content": removeScript,
		"reserved_Action":  "uninstall",
	})
	if err != nil {
		return false, api.RemoveResults{}, err
	}
	filename := fmt.Sprintf("/var/tmp/%s_uninstall.sh", c.BaseFilename())
	err = uploadStringToTargetFile(cmdStr, host, filename)
	if err != nil {
		return false, api.RemoveResults{}, err
	}

	cmd := fmt.Sprintf("sudo bash %s; rc=$?; sudo rm -f %s; exit $rc", filename, filename)
	duration := specs.GetInt("component.installing.script.estimated_execution_time")
	if duration == 0 {
		duration = 5
	}
	retcode, _, _, err := client.New().Ssh.Run(host.ID, cmd, time.Duration(duration)*time.Minute)
	if err != nil {
		return false, api.RemoveResults{}, err
	}
	var status error
	ok := retcode == 0
	if !ok {
		status = fmt.Errorf("uninstall script for component '%s' failed, retcode=%d", c.DisplayName(), retcode)
	}
	return ok, api.RemoveResults{
		AddResults: api.AddResults{
			PrivateNodes: map[string]error{
				host.Name: status,
			},
		},
	}, nil
}

// removeFromCluster uninstalled a component from a cluster
func (i *scriptInstaller) removeFromCluster(c api.Component, cluster clusterapi.ClusterAPI) (bool, api.RemoveResults, error) {
	specs := c.Specs()
	masterT, privnodeT, pubnodeT, err := validateClusterTargets(specs)
	if err != nil {
		return false, api.RemoveResults{}, err
	}

	var (
		mastersChannel   chan map[string]error
		privnodesChannel chan map[string]error
		pubnodesChannel  chan map[string]error
		mastersStatus    = map[string]error{}
		privnodesStatus  = map[string]error{}
		pubnodesStatus   = map[string]error{}
		checked          int
	)

	var list []string
	if masterT != "0" {
		if masterT == "1" {
			hostID, err := findConcernedHosts(cluster.ListMasterIDs(), c)
			if err != nil {
				return false, api.RemoveResults{}, err
			}
			list = []string{hostID}
		} else {
			list = cluster.ListMasterIDs()
		}
		mastersChannel = make(chan map[string]error)
		go asyncRemoveFromHosts(list, c, mastersChannel)
		checked += len(list)
	}
	if privnodeT != "0" {
		if privnodeT == "1" {
			hostID, err := findConcernedHosts(cluster.ListNodeIDs(false), c)
			if err != nil {
				return false, api.RemoveResults{}, err
			}
			list = []string{hostID}
		} else {
			list = cluster.ListNodeIDs(false)
		}
		privnodesChannel = make(chan map[string]error)
		go asyncRemoveFromHosts(list, c, privnodesChannel)
		checked += len(list)
	}
	if pubnodeT != "0" {
		if pubnodeT == "1" {
			hostID, err := findConcernedHosts(cluster.ListNodeIDs(true), c)
			if err != nil {
				return false, api.RemoveResults{}, err
			}
			list = []string{hostID}
		} else {
			list = cluster.ListNodeIDs(true)
		}
		pubnodesChannel = make(chan map[string]error)
		go asyncRemoveFromHosts(list, c, pubnodesChannel)
		checked += len(list)
	}

	ok := true
	if masterT != "0" {
		mastersStatus = <-mastersChannel
		for _, i := range mastersStatus {
			if i != nil {
				ok = false
				break
			}
		}
	}
	privnodesStatus = map[string]error{}
	if privnodeT != "0" {
		privnodesStatus = <-privnodesChannel
		for _, i := range privnodesStatus {
			if i != nil {
				ok = false
				break
			}
		}
	}
	pubnodesStatus = map[string]error{}
	if pubnodeT != "0" {
		pubnodesStatus = <-pubnodesChannel
		for _, i := range pubnodesStatus {
			if i != nil {
				ok = false
				break
			}
		}
	}
	if checked <= 0 {
		return false, api.RemoveResults{}, fmt.Errorf("no hosts selected to remove from")
	}
	return ok, api.RemoveResults{
		AddResults: api.AddResults{
			Masters:      mastersStatus,
			PrivateNodes: privnodesStatus,
			PublicNodes:  pubnodesStatus,
		},
	}, nil
}

// NewScriptInstaller creates a new instance of Installer using script
func NewScriptInstaller() api.Installer {
	return &scriptInstaller{}
}
