package install

import (
	"fmt"
	"log"
	"strings"
	"time"

	pb "github.com/CS-SI/SafeScale/broker"

	brokerclient "github.com/CS-SI/SafeScale/broker/client"

	clusterapi "github.com/CS-SI/SafeScale/deploy/cluster/api"
)

const (
	componentScriptTemplateContent = `
rm -f /var/tmp/{{.reserved_Name}}.component.{{.reserved_Action}}.log
exec 1<&-
exec 2<&-
exec 1<>/var/tmp/{{.reserved_Name}}.component.{{.reserved_Action}}.log
exec 2>&1

{{ .reserved_BashLibrary }}

{{ .reserved_Content }}
`
)

// bashInstaller is an installer using script to add and remove a component
type bashInstaller struct{}

func (i *bashInstaller) GetName() string {
	return "script"
}

// Check checks if the component is installed, using the check script in Specs
func (i *bashInstaller) Check(c *Component, t Target, v Variables) (bool, CheckResults, error) {
	specs := c.Specs()
	if !specs.IsSet("component.install.bash.check") {
		msg := `syntax error in component '%s' specification file (%s):
				no key 'component.install.bash.check' found`
		return false, CheckResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}

	hostTarget, clusterTarget, nodeTarget := determineContext(t)

	// Host target
	if hostTarget != nil {
		if specs.IsSet("component.target.host") {
			target := strings.ToLower(specs.GetString("component.target.host"))
			if target != "yes" && target != "true" {
				return false, CheckResults{}, fmt.Errorf("can't check, component doesn't target a host")
			}
		}
		return i.checkOnHost(c, hostTarget.host, v)
	}
	// Cluster target
	if clusterTarget != nil {
		return i.checkOnCluster(c, clusterTarget.cluster, v)
	}
	// Node target (== Host Target without verifying if the component is targetting a host)
	if nodeTarget != nil {
		return i.checkOnHost(c, nodeTarget.host, v)
	}

	return false, CheckResults{}, fmt.Errorf("type of target is unknown")
}

func (i *bashInstaller) checkOnHost(c *Component, host *pb.Host, v Variables) (bool, CheckResults, error) {
	specs := c.Specs()
	// Normalize script to check
	checkScript := specs.GetString("component.install.bash.check")
	if strings.TrimSpace(checkScript) == "" {
		msg := `syntax error in component '%s' specification file (%s):
				key 'component.install.bash.check' is empty`
		return false, CheckResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}
	cmdStr, err := normalizeScript(Variables{
		"reserved_Name":    c.BaseFilename(),
		"reserved_Content": checkScript,
		"reserved_Action":  "check",
	})
	if err != nil {
		return false, CheckResults{}, fmt.Errorf("failed to prepare check script: %s", err.Error())
	}

	// Sets some implicit variables for clusters
	if _, ok := v["Username"]; !ok {
		v["Username"] = "gpac"
	}

	// Replaces variables in normalized script
	cmdStr, err = replaceVariablesInString(cmdStr, v)
	if err != nil {
		return false, CheckResults{}, fmt.Errorf("failed to finalize check script: %s", err.Error())
	}

	// Uploads then executes normalized script
	filename := fmt.Sprintf("/var/tmp/%s_check.sh", c.BaseFilename())
	err = UploadStringToRemoteFile(cmdStr, host, filename, "", "", "")
	if err != nil {
		return false, CheckResults{}, fmt.Errorf("failed to upload check script to host '%s': %s", host.Name, err.Error())
	}
	var cmd string
	// if debug {
	if false {
		cmd = fmt.Sprintf("sudo bash %s", filename)
	} else {
		cmd = fmt.Sprintf("sudo bash %s; rc=$?; sudo rm -f %s; exit $rc", filename, filename)
	}
	retcode, _, _, err := brokerclient.New().Ssh.Run(host.ID, cmd, brokerclient.DefaultConnectionTimeout, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		return false, CheckResults{}, fmt.Errorf("failed to execute remotely check script: %s", err.Error())
	}
	ok := retcode == 0
	return ok, CheckResults{host.Name: CheckState{Success: true, Present: ok}}, nil
}

func (i *bashInstaller) checkOnCluster(
	c *Component, cluster clusterapi.Cluster, v Variables,
) (bool, CheckResults, error) {

	if !validateContextForCluster(c, cluster) {
		config := cluster.GetConfig()
		msg := fmt.Sprintf("component not permitted on flavor '%s' of cluster '%s'\n", config.Flavor.String(), config.Name)
		log.Println(msg)
		return false, CheckResults{}, fmt.Errorf(msg)
	}

	specs := c.Specs()
	masterT, privnodeT, pubnodeT, err := validateClusterTargets(specs)
	if err != nil {
		return false, CheckResults{}, err
	}

	var (
		mastersChannel   chan map[string]CheckState
		privnodesChannel chan map[string]CheckState
		pubnodesChannel  chan map[string]CheckState
		mastersStatus    = map[string]CheckState{}
		privnodesStatus  = map[string]CheckState{}
		pubnodesStatus   = map[string]CheckState{}
		checked          int
		hostsResults     = map[string]CheckState{}
	)

	// Sets some implicit variables for clusters
	v["MasterIDs"] = cluster.ListMasterIDs()
	v["MasterIPs"] = cluster.ListMasterIPs()
	if _, ok := v["Username"]; !ok {
		v["Username"] = "cladm"
	}

	if masterT != "0" {
		mastersChannel = make(chan map[string]CheckState)
		list := cluster.ListMasterIDs()
		checked += len(list)
		go asyncCheckHosts(list, c, v, mastersChannel)
	}
	if privnodeT != "0" {
		privnodesChannel = make(chan map[string]CheckState)
		list := cluster.ListNodeIDs(false)
		checked += len(list)
		go asyncCheckHosts(list, c, v, privnodesChannel)
	}
	if pubnodeT != "0" {
		pubnodesChannel = make(chan map[string]CheckState)
		list := cluster.ListNodeIDs(true)
		checked += len(list)
		go asyncCheckHosts(list, c, v, pubnodesChannel)
	}

	ok := true
	if masterT != "0" {
		mastersStatus = <-mastersChannel
		for h, k := range mastersStatus {
			hostsResults[h] = k
			if ok && (!k.Success || !k.Present) {
				ok = false
			}
		}
	}
	if privnodeT != "0" {
		privnodesStatus = <-privnodesChannel
		for h, k := range privnodesStatus {
			hostsResults[h] = k
			if ok && (!k.Success || !k.Present) {
				ok = false
			}
		}
	}
	if pubnodeT != "0" {
		pubnodesStatus = <-pubnodesChannel
		for h, k := range pubnodesStatus {
			hostsResults[h] = k
			if ok && (!k.Success || !k.Present) {
				ok = false
				break
			}
		}
	}
	// If no hosts have been selected to check state, don't say it's installed
	if checked <= 0 {
		return false, CheckResults{}, fmt.Errorf("no hosts selected to be checked")
	}
	return ok, hostsResults, nil
}

// Add installs the component using the install script in Specs
// 'values' contains the values associated with parameters as defined in specification file
func (i *bashInstaller) Add(c *Component, t Target, v Variables) (bool, AddResults, error) {
	specs := c.Specs()
	// If component is installed, do nothing but responds with success
	ok, _, err := i.Check(c, t, v)
	if err != nil {
		return false, AddResults{}, fmt.Errorf("component '%s' check failed: %s", c.DisplayName(), err.Error())
	}
	if ok {
		log.Printf("Component '%s' is already installed\n", c.DisplayName())
		return true, AddResults{}, nil
	}

	// Inits implicit parameters
	setImplicitParameters(t, v)

	// Checks required parameters have value
	err = checkParameters(c, v)
	if err != nil {
		return false, AddResults{}, err
	}

	// First, installs requirements if there are any
	err = installRequirements(c, t, v)
	if err != nil {
		return false, AddResults{}, fmt.Errorf("failed to install requirements: %s", err.Error())
	}

	// Determining if install script is defined in specification file
	if !specs.IsSet("component.install.bash.add") {
		msg := `syntax error in component '%s' specification file (%s):
				no key 'component.install.bash.add' found`
		return false, AddResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}

	hostTarget, clusterTarget, nodeTarget := determineContext(t)

	if hostTarget != nil {
		if specs.IsSet("component.target.host") {
			target := strings.ToLower(specs.GetString("component.target.host"))
			if target != "yes" && target != "true" {
				return false, AddResults{}, fmt.Errorf("can't install, component doesn't target a host")
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

	return false, AddResults{}, fmt.Errorf("type of target is unknown")
}

// addOnHost installs a component on an host
func (i *bashInstaller) addOnHost(
	c *Component,
	host *pb.Host,
	v Variables,
) (bool, AddResults, error) {

	specs := c.Specs()
	// Build template script
	addScript := specs.GetString("component.install.bash.add")
	if strings.TrimSpace(addScript) == "" {
		msg := `syntax error in component '%s' specification file (%s):
				key 'component.install.bash.add' is empty`
		return false, AddResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}
	cmdStr, err := normalizeScript(Variables{
		"reserved_Name":    c.BaseFilename(),
		"reserved_Content": addScript,
		"reserved_Action":  "add",
	})
	if err != nil {
		return false, AddResults{}, fmt.Errorf("failed to normalize script: %s", err.Error())
	}

	// Sets some implicit variables for hosts
	if _, ok := v["Username"]; !ok {
		v["Username"] = "gpac"
	}

	// Replaces variables in install script
	cmdStr, err = replaceVariablesInString(cmdStr, v)
	if err != nil {
		return false, AddResults{}, fmt.Errorf("failed to finalize check script: %s", err.Error())
	}

	// Uploads final script
	filename := fmt.Sprintf("/var/tmp/%s_add.sh", c.BaseFilename())
	err = UploadStringToRemoteFile(cmdStr, host, filename, "", "", "")
	if err != nil {
		return false, AddResults{}, fmt.Errorf("failed to upload add script on remote host: %s", err.Error())
	}

	// Runs final script on target
	var cmd string
	// if debug {
	if true {
		cmd = fmt.Sprintf("sudo bash %s", filename)
	} else {
		cmd = fmt.Sprintf("sudo bash %s; rc=$?; sudo rm -f %s; exit $rc", filename, filename)
	}
	wallTime := specs.GetInt("component.install.bash.wall_time")
	if wallTime == 0 {
		wallTime = 5
	}
	retcode, _, _, err := brokerclient.New().Ssh.Run(host.ID, cmd, 30*time.Second, time.Duration(wallTime)*time.Minute)
	if err != nil {
		return false, AddResults{}, fmt.Errorf("failed to execute install script on host '%s': %s", host.Name, err.Error())
	}
	ok := retcode == 0
	err = nil
	if !ok {
		err = fmt.Errorf("install script failed (retcode=%d)", retcode)
	} else {
		if ok && specs.IsSet("component.proxy.rules") {
			err = proxyComponent(c, host)
			ok = err == nil
		}
	}
	return ok, AddResults{host.Name: stepErrors{"__error__": err}}, err
}

// addOnCluster installs a component on a cluster
func (i *bashInstaller) addOnCluster(
	c *Component, cluster clusterapi.Cluster, v Variables,
) (bool, AddResults, error) {

	if !validateContextForCluster(c, cluster) {
		config := cluster.GetConfig()
		msg := fmt.Sprintf("component not permitted on flavor '%s' of cluster '%s'\n", config.Flavor.String(), config.Name)
		log.Println(msg)
		return false, AddResults{}, fmt.Errorf(msg)
	}

	specs := c.Specs()
	masterT, privnodeT, pubnodeT, err := validateClusterTargets(specs)
	if err != nil {
		return false, AddResults{}, err
	}

	// Sets some implicit variables for clusters
	v["MasterIDs"] = cluster.ListMasterIDs()
	v["MasterIPs"] = cluster.ListMasterIPs()
	if _, ok := v["Username"]; !ok {
		v["Username"] = "cladm"
	}

	var (
		mastersChannel   chan map[string]stepErrors
		privnodesChannel chan map[string]stepErrors
		pubnodesChannel  chan map[string]stepErrors
		list             []string
		mastersStatus    = map[string]stepErrors{}
		privnodesStatus  = map[string]stepErrors{}
		pubnodesStatus   = map[string]stepErrors{}
		checked          int
	)

	v["MasterIDs"] = cluster.ListMasterIDs()
	v["MasterIPs"] = cluster.ListMasterIPs()
	//v["DomainName"] = cluster.GetConfig().DomainName

	if masterT != "0" {
		if masterT == "1" {
			hostID, err := cluster.FindAvailableMaster()
			if err != nil {
				return false, AddResults{}, err
			}
			list = []string{hostID}
		} else {
			list = cluster.ListMasterIDs()
		}
		mastersChannel = make(chan map[string]stepErrors)
		go asyncAddOnHosts(list, c, v, mastersChannel)
		checked += len(list)
	}
	if privnodeT != "0" {
		if privnodeT == "1" {
			hostID, err := cluster.FindAvailableNode(false)
			if err != nil {
				return false, AddResults{}, err
			}
			list = []string{hostID}
		} else {
			list = cluster.ListNodeIDs(false)
		}
		privnodesChannel = make(chan map[string]stepErrors)
		go asyncAddOnHosts(list, c, v, privnodesChannel)
		checked += len(list)
	}
	if pubnodeT != "0" {
		if pubnodeT == "1" {
			hostID, err := cluster.FindAvailableNode(true)
			if err != nil {
				return false, AddResults{}, err
			}
			list = []string{hostID}
		} else {
			list = cluster.ListNodeIDs(true)
		}
		pubnodesChannel = make(chan map[string]stepErrors)
		go asyncAddOnHosts(list, c, v, pubnodesChannel)
		checked += len(list)
	}

	ok := true
	hostsResults := map[string]stepErrors{}
	if masterT != "0" {
		mastersStatus = <-mastersChannel
		for h, se := range mastersStatus {
			hostsResults[h] = se
			if ok && len(se) > 0 {
				ok = false
			}
		}
	}
	privnodesStatus = map[string]stepErrors{}
	if privnodeT != "0" {
		privnodesStatus = <-privnodesChannel
		for h, se := range privnodesStatus {
			hostsResults[h] = se
			if ok && len(se) > 0 {
				ok = false
				break
			}
		}
	}
	pubnodesStatus = map[string]stepErrors{}
	if pubnodeT != "0" {
		pubnodesStatus = <-pubnodesChannel
		for h, se := range pubnodesStatus {
			hostsResults[h] = se
			if ok && len(se) > 0 {
				ok = false
				break
			}
		}
	}
	if checked <= 0 {
		return false, AddResults{}, fmt.Errorf("no hosts selected to install on")
	}
	return ok, hostsResults, nil
}

// Remove uninstalls the component
func (i *bashInstaller) Remove(c *Component, t Target, v Variables) (bool, RemoveResults, error) {

	specs := c.Specs()
	if !specs.IsSet("component.install.bash.remove") {
		msg := `syntax error in component '%s' specification file (%s):
				no key 'component.install.bash.remove' found`
		return false, RemoveResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}

	hostTarget, clusterTarget, nodeTarget := determineContext(t)

	if hostTarget != nil {
		if specs.IsSet("component.target.host") {
			target := strings.ToLower(specs.GetString("component.target.host"))
			if target != "yes" && target != "true" {
				return false, RemoveResults{}, fmt.Errorf("can't install, component doesn't target a host")
			}
		}
		return i.removeFromHost(c, hostTarget.host, v)
	}
	if clusterTarget != nil {
		return i.removeFromCluster(c, clusterTarget.cluster, v)
	}
	if nodeTarget != nil {
		return i.removeFromHost(c, hostTarget.host, v)
	}
	return false, RemoveResults{}, fmt.Errorf("type of target is unknown")
}

// removeFromHost uninstalls a component from a host
func (i *bashInstaller) removeFromHost(c *Component, host *pb.Host, v Variables) (bool, RemoveResults, error) {
	specs := c.Specs()
	// Normalize script to uninstall
	removeScript := specs.GetString("component.install.bash.remove")
	if strings.TrimSpace(removeScript) == "" {
		msg := `syntax error in component '%s' specification file (%s):
		        key 'component.install.bash.remove' is empty`
		return false, RemoveResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}
	cmdStr, err := normalizeScript(Variables{
		"reserved_Name":    c.BaseFilename(),
		"reserved_Content": removeScript,
		"reserved_Action":  "remove",
	})
	if err != nil {
		return false, RemoveResults{}, err
	}

	// Replaces variables in install script
	cmdStr, err = replaceVariablesInString(cmdStr, v)
	if err != nil {
		return false, RemoveResults{}, fmt.Errorf("failed to finalize check script: %s", err.Error())
	}

	// Uploads then executes normalized script
	filename := fmt.Sprintf("/var/tmp/%s_remove.sh", c.BaseFilename())
	err = UploadStringToRemoteFile(cmdStr, host, filename, "", "", "")
	if err != nil {
		return false, RemoveResults{}, err
	}
	var cmd string
	// if debug {
	if false {
		cmd = fmt.Sprintf("sudo bash %s; rc=$?; exit $rc", filename)
	} else {
		cmd = fmt.Sprintf("sudo bash %s; rc=$?; sudo rm -f %s; exit $rc", filename, filename)
	}
	wallTime := specs.GetInt("component.install.bash.wall_time")
	if wallTime == 0 {
		wallTime = 5
	}
	retcode, _, _, err := brokerclient.New().Ssh.Run(host.ID, cmd, 30*time.Second, time.Duration(wallTime)*time.Minute)
	if err != nil {
		return false, RemoveResults{}, err
	}
	err = nil
	ok := retcode == 0
	if !ok {
		err = fmt.Errorf("remove script for component '%s' failed, retcode=%d", c.DisplayName(), retcode)
	}
	return ok, RemoveResults{AddResults: AddResults{
		host.Name: stepErrors{"__error__": err},
	}}, err
}

// removeFromCluster uninstalled a component from a cluster
func (i *bashInstaller) removeFromCluster(
	c *Component,
	cluster clusterapi.Cluster,
	v Variables,
) (bool, RemoveResults, error) {

	if !validateContextForCluster(c, cluster) {
		config := cluster.GetConfig()
		msg := fmt.Sprintf("component not permitted on flavor '%s' of cluster '%s'\n", config.Flavor.String(), config.Name)
		log.Println(msg)
		return false, RemoveResults{}, fmt.Errorf(msg)
	}

	specs := c.Specs()
	masterT, privnodeT, pubnodeT, err := validateClusterTargets(specs)
	if err != nil {
		return false, RemoveResults{}, err
	}

	// Sets some implicit variables for clusters
	v["MasterIDs"] = cluster.ListMasterIDs()
	v["MasterIPs"] = cluster.ListMasterIPs()
	if _, ok := v["Username"]; !ok {
		v["Username"] = "cladm"
	}

	var (
		hostsResults     = RemoveResults{}
		mastersChannel   chan map[string]stepErrors
		privnodesChannel chan map[string]stepErrors
		pubnodesChannel  chan map[string]stepErrors
		checked          int
	)

	var list []string
	if masterT != "0" {
		if masterT == "1" {
			hostID, err := findConcernedHosts(cluster.ListMasterIDs(), c)
			if err != nil {
				return false, RemoveResults{}, err
			}
			list = []string{hostID}
		} else {
			list = cluster.ListMasterIDs()
		}
		mastersChannel = make(chan map[string]stepErrors)
		go asyncRemoveFromHosts(list, c, v, mastersChannel)
		checked += len(list)
	}
	if privnodeT != "0" {
		if privnodeT == "1" {
			hostID, err := findConcernedHosts(cluster.ListNodeIDs(false), c)
			if err != nil {
				return false, RemoveResults{}, err
			}
			list = []string{hostID}
		} else {
			list = cluster.ListNodeIDs(false)
		}
		privnodesChannel = make(chan map[string]stepErrors)
		go asyncRemoveFromHosts(list, c, v, privnodesChannel)
		checked += len(list)
	}
	if pubnodeT != "0" {
		if pubnodeT == "1" {
			hostID, err := findConcernedHosts(cluster.ListNodeIDs(true), c)
			if err != nil {
				return false, RemoveResults{}, err
			}
			list = []string{hostID}
		} else {
			list = cluster.ListNodeIDs(true)
		}
		pubnodesChannel = make(chan map[string]stepErrors)
		go asyncRemoveFromHosts(list, c, v, pubnodesChannel)
		checked += len(list)
	}

	ok := true
	if masterT != "0" {
		mastersStatus := <-mastersChannel
		for h, se := range mastersStatus {
			hostsResults.AddResults[h] = se
			if ok && len(se) > 0 {
				ok = false
			}
		}
	}
	if privnodeT != "0" {
		privnodesStatus := <-privnodesChannel
		for h, se := range privnodesStatus {
			hostsResults.AddResults[h] = se
			if ok && len(se) > 0 {
				ok = false
			}
		}
	}
	if pubnodeT != "0" {
		pubnodesStatus := <-pubnodesChannel
		for h, se := range pubnodesStatus {
			hostsResults.AddResults[h] = se
			if ok && len(se) > 0 {
				ok = false
			}
		}
	}
	if checked <= 0 {
		return false, RemoveResults{}, fmt.Errorf("no hosts selected to remove from")
	}
	return ok, hostsResults, nil
}

// NewBashInstaller creates a new instance of Installer using script
func NewBashInstaller() Installer {
	return &bashInstaller{}
}
