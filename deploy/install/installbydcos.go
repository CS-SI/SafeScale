package install

import (
	"fmt"
	"strings"
	"time"

	brokerclient "github.com/CS-SI/SafeScale/broker/client"

	"github.com/CS-SI/SafeScale/deploy/install/api"

	"github.com/CS-SI/SafeScale/deploy/cluster/api/Complexity"
)

const (
	dcosCli    = "sudo -u cladm -i dcos"
	kubectlCli = "sudo -u cladm -i kubectl"
)

// dcosInstaller is an installer using script to add and remove a component
type dcosInstaller struct{}

func (i *dcosInstaller) GetName() string {
	return "dcos"
}

// Check checks if the component is installed
func (i *dcosInstaller) Check(c api.Component, t api.Target, v api.Variables) (bool, api.CheckResults, error) {
	specializedTarget, ok := t.(*ClusterTarget)
	if !ok {
		return false, api.CheckResults{}, fmt.Errorf("target isn't a cluster")
	}

	specs := c.Specs()
	// Note: In special case of DCOS, installation is done on any master available. values returned
	// by validateClusterTargets() are ignored
	_, _, _, err := validateClusterTargets(specs)
	if err != nil {
		return false, api.CheckResults{}, err
	}

	if !specs.IsSet("component.install.dcos.check") {
		msg := `syntax error in component '%s' specification file (%s):
				no key 'component.install.dcos.check' found`
		return false, api.CheckResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}
	checkScript := specs.GetString("component.install.dcos.check")
	if strings.TrimSpace(checkScript) == "" {
		msg := `syntax error in component '%s' specification file (%s):
				key 'component.install.dcos.check' is empty`
		return false, api.CheckResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}

	cluster := specializedTarget.cluster

	hostID, err := cluster.FindAvailableMaster()
	if err != nil {
		return false, api.CheckResults{}, err
	}
	broker := brokerclient.New()
	host, err := broker.Host.Inspect(hostID, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		return false, api.CheckResults{}, err
	}
	cmdStr, err := normalizeScript(api.Variables{
		"reserved_Name":    c.BaseFilename(),
		"reserved_Content": checkScript,
		"reserved_Action":  "check",
	})
	if err != nil {
		return false, api.CheckResults{}, err
	}

	// Replaces variables in normalized script
	v["MasterIDs"] = cluster.ListMasterIDs()
	v["MasterIPs"] = cluster.ListMasterIPs()
	//v["DomainName"] = cluster.GetConfig().DomainName
	v["dcos"] = dcosCli
	cmdStr, err = replaceVariablesInString(cmdStr, v)
	if err != nil {
		return false, api.CheckResults{}, fmt.Errorf("failed to finalize check script: %s", err.Error())
	}

	// Uploads the executes the script
	filename := fmt.Sprintf("/var/tmp/%s_check.sh", c.BaseFilename())
	err = UploadStringToRemoteFile(cmdStr, host, filename, "", "", "u+rw-x,go-rwx")
	if err != nil {
		return false, api.CheckResults{}, err
	}
	var cmd string
	//if debug {
	if false {
		cmd = fmt.Sprintf("sudo bash %s", filename)
	} else {
		cmd = fmt.Sprintf("sudo bash %s; rc=$?; sudo rm -f %s; exit $rc", filename, filename)
	}
	wallTime := specs.GetInt("component.install.dcos.wall_time")
	if wallTime == 0 {
		wallTime = 5
	}

	retcode, _, _, err := broker.Ssh.Run(hostID, cmd, brokerclient.DefaultConnectionTimeout, time.Duration(wallTime)*time.Minute)
	if err != nil {
		return false, api.CheckResults{}, err
	}
	ok = retcode == 0
	return ok, api.CheckResults{
		Masters: map[string]api.CheckState{
			host.Name: api.CheckState{
				Success: true,
				Present: ok,
			},
		},
	}, nil
}

// Add installs the component using apt
func (i *dcosInstaller) Add(c api.Component, t api.Target, v api.Variables) (bool, api.AddResults, error) {
	clusterTarget, ok := t.(*ClusterTarget)
	if !ok {
		return false, api.AddResults{}, fmt.Errorf("target isn't a cluster")
	}
	specs := c.Specs()
	_, _, _, err := validateClusterTargets(specs)
	if err != nil {
		return false, api.AddResults{}, err
	}

	if !specs.IsSet("component.install.dcos.add") {
		msg := `syntax error in component '%s' specification file (%s):
				no key 'component.install.dcos.add' found`
		return false, api.AddResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}
	addScript := specs.GetString("component.install.dcos.add")
	if strings.TrimSpace(addScript) == "" {
		msg := `syntax error in component '%s' specification file (%s):
				key 'component.install.dcos.add' is empty`
		return false, api.AddResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}

	cluster := clusterTarget.cluster

	hostID, err := cluster.FindAvailableMaster()
	if err != nil {
		return false, api.AddResults{}, err
	}
	broker := brokerclient.New()
	host, err := broker.Host.Inspect(hostID, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		return false, api.AddResults{}, err
	}
	cmdStr, err := normalizeScript(api.Variables{
		"reserved_Name":    c.BaseFilename(),
		"reserved_Content": addScript,
		"reserved_Action":  "add",
	})
	if err != nil {
		return false, api.AddResults{}, err
	}

	// Replaces variables in normalized script
	v["MasterIDs"] = cluster.ListMasterIDs()
	v["MasterIPs"] = cluster.ListMasterIPs()
	//v["DomainName"] = cluster.GetConfig().DomainName
	v["dcos"] = dcosCli
	v["kubectl"] = kubectlCli
	v["options"] = ""
	if specs.IsSet("component.install.dcos.options") {
		var (
			avails  = map[string]interface{}{}
			ok      bool
			content interface{}
		)
		complexity := strings.ToLower(cluster.GetConfig().Complexity.String())
		options := specs.GetStringMap("component.install.dcos.options")
		for k, anon := range options {
			avails[strings.ToLower(k)] = anon
		}
		if content, ok = avails[complexity]; !ok {
			if complexity == Complexity.Volume.String() {
				complexity = Complexity.Normal.String()
			}
			if complexity == Complexity.Normal.String() {
				if content, ok = avails[complexity]; !ok {
					content, ok = avails[Complexity.Minimal.String()]
				}
			}
		}
		if ok {
			err := UploadStringToRemoteFile(content.(string), host, "/var/tmp/options.json", "cladm", "", "u+rw-x,go-rwx")
			if err != nil {
				return false, api.AddResults{}, err
			}
			v["options"] = "--options=/var/tmp/options.json"
		}
	}
	cmdStr, err = replaceVariablesInString(cmdStr, v)
	if err != nil {
		return false, api.AddResults{}, fmt.Errorf("failed to finalize install script: %s", err.Error())
	}

	// Uploads then executes command
	filename := fmt.Sprintf("/var/tmp/%s_add.sh", c.BaseFilename())
	err = UploadStringToRemoteFile(cmdStr, host, filename, "", "", "")
	if err != nil {
		return false, api.AddResults{}, err
	}
	var cmd string
	//if debug {
	if true {
		cmd = fmt.Sprintf("sudo bash %s", filename)
	} else {
		cmd = fmt.Sprintf("sudo bash %s; rc=$?; sudo rm -f %s /var/tmp/options.json; exit $rc", filename, filename)
	}
	wallTime := specs.GetInt("component.install.dcos.wall_time")
	if wallTime == 0 {
		wallTime = 5
	}
	retcode, _, _, err := broker.Ssh.Run(hostID, cmd, brokerclient.DefaultConnectionTimeout, time.Duration(wallTime)*time.Minute)
	if err != nil {
		return false, api.AddResults{}, err
	}
	err = nil
	ok = retcode == 0
	if !ok {
		err = fmt.Errorf("install script for component '%s' failed, retcode=%d", c.DisplayName(), retcode)
	}
	return ok, api.AddResults{
		Masters: map[string]error{
			host.Name: err,
		},
	}, err
}

// Remove uninstalls the component using the RemoveScript script
// usage: ok, results, err := i.Remove(c, t)
// - if err != nil, the removal wasn't submitted successfully and err contains why
// - if err == nil and ok ==true, removal wa submitted and succeeded
// - if err == nil and ok == false, removal was submitted successfully but failed, results contain reasons
//   of failures on what parts
func (i *dcosInstaller) Remove(c api.Component, t api.Target, v api.Variables) (bool, api.RemoveResults, error) {
	specializedTarget, ok := t.(*ClusterTarget)
	if !ok {
		return false, api.RemoveResults{}, fmt.Errorf("target isn't a cluster")
	}
	specs := c.Specs()
	_, _, _, err := validateClusterTargets(specs)
	if err != nil {
		return false, api.RemoveResults{}, err
	}
	// Note: In special case of DCOS, removal is done on any master available. values returned
	// by clusterTargets() are ignored

	if !specs.IsSet("component.install.dcos.remove") {
		msg := `syntax error in component '%s' specification file (%s):
				no key 'component.install.dcos.remove' found`
		return false, api.RemoveResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}
	removeScript := specs.GetString("component.install.dcos.remove")
	if strings.TrimSpace(removeScript) == "" {
		msg := `syntax error in component '%s' specification file (%s):
				key 'component.install.dcos.remove' is empty`
		return false, api.RemoveResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}

	cluster := specializedTarget.cluster
	hostID, err := cluster.FindAvailableMaster()
	if err != nil {
		return false, api.RemoveResults{}, err
	}
	broker := brokerclient.New()
	host, err := broker.Host.Inspect(hostID, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		return false, api.RemoveResults{}, err
	}

	// Normalizes script
	cmdStr, err := normalizeScript(api.Variables{
		"reserved_Name":    c.BaseFilename(),
		"reserved_Content": removeScript,
		"reserved_Action":  "remove",
	})
	if err != nil {
		return false, api.RemoveResults{}, err
	}

	// Replaces variables in normalized script
	v["MasterIDs"] = cluster.ListMasterIDs()
	v["MasterIPs"] = cluster.ListMasterIPs()
	//v["DomainName"] = cluster.GetConfig().DomainName
	v["dcos"] = dcosCli
	cmdStr, err = replaceVariablesInString(cmdStr, v)
	if err != nil {
		return false, api.RemoveResults{}, fmt.Errorf("failed to finalize install script: %s", err.Error())
	}

	// Uploads then executes script
	filename := fmt.Sprintf("/var/tmp/%s_remove.sh", c.BaseFilename())
	err = UploadStringToRemoteFile(cmdStr, host, filename, "", "", "")
	if err != nil {
		return false, api.RemoveResults{}, err
	}
	var cmd string
	//if debug {
	if false {
		cmd = fmt.Sprintf("sudo bash %s", filename)
	} else {
		cmd = fmt.Sprintf("sudo bash %s; rc=$?; sudo rm -f %s; exit $rc", filename, filename)
	}
	wallTime := specs.GetInt("component.install.dcos.wall_time")
	if wallTime == 0 {
		wallTime = 5
	}

	retcode, _, _, err := broker.Ssh.Run(hostID, cmd, brokerclient.DefaultConnectionTimeout, time.Duration(wallTime)*time.Minute)
	if err != nil {
		return false, api.RemoveResults{}, err
	}
	ok = retcode == 0
	if !ok {
		err = fmt.Errorf("uninstall script for component '%s' failed, retcode=%d", c.DisplayName(), retcode)
	}
	return ok, api.RemoveResults{
		AddResults: api.AddResults{
			Masters: map[string]error{
				host.Name: err,
			},
		},
	}, err
}

// NewDcosInstaller creates a new instance of Installer using DCOS
func NewDcosInstaller() api.Installer {
	return &dcosInstaller{}
}
