package install

import (
	"fmt"
	"strings"
	"time"

	brokerclient "github.com/CS-SI/SafeScale/broker/client"

	"github.com/CS-SI/SafeScale/deploy/install/api"
)

const (
	dcosCli = "sudo -u cladm -i"
)

// dcosInstaller is an installer using script to add and remove a component
type dcosInstaller struct{}

func (i *dcosInstaller) GetName() string {
	return "dcos"
}

// Check checks if the component is installed
func (i *dcosInstaller) Check(c api.Component, t api.Target) (bool, api.CheckResults, error) {
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

	if !specs.IsSet("component.installing.dcos.check") {
		msg := `syntax error in component '%s' specification file (%s):
				no key 'component.installing.dcos.check' found`
		return false, api.CheckResults{}, fmt.Errorf(msg, c.DisplayName(), c.FullFileName())
	}
	checkScript := specs.GetString("component.installing.dcos.check")
	if strings.TrimSpace(checkScript) == "" {
		msg := `syntax error in component '%s' specification file (%s):
				key 'component.installing.dcos.check' is empty`
		return false, api.CheckResults{}, fmt.Errorf(msg, c.DisplayName(), c.FullFileName())
	}

	cluster := specializedTarget.cluster
	values := map[string]interface{}{
		"reserved_Name":    c.ShortFileName(),
		"reserved_Content": checkScript,
		"reserved_Action":  "check",
		"MasterIDs":        cluster.ListMasterIDs(),
		"MasterIPs":        cluster.ListMasterIPs(),
		//"DomainName":       cluster.GetConfig().DomainName,
		"dcos": dcosCli,
	}
	hostID, err := cluster.FindAvailableMaster()
	if err != nil {
		return false, api.CheckResults{}, err
	}
	broker := brokerclient.New()
	host, err := broker.Host.Inspect(hostID, brokerclient.DefaultTimeout)
	if err != nil {
		return false, api.CheckResults{}, err
	}
	cmdStr, err := realizeScript(values)
	if err != nil {
		return false, api.CheckResults{}, err
	}
	filename := fmt.Sprintf("/var/tmp/%s_check.sh", c.ShortFileName())
	err = uploadStringToTargetFile(cmdStr, host, filename)
	if err != nil {
		return false, api.CheckResults{}, err
	}
	cmd := fmt.Sprintf("sudo bash %s; rc=$?; sudo rm -f %s; exit $rc", filename, filename)
	duration := specs.GetInt("component.installing.dcos.duration")
	if duration == 0 {
		duration = 5
	}

	retcode, _, _, err := broker.Ssh.Run(hostID, cmd, time.Duration(duration)*time.Minute)
	if err != nil {
		return false, api.CheckResults{}, err
	}
	status := api.ComponentPresent
	ok = retcode == 0
	if !ok {
		status = api.ComponentAbsent
	}
	return ok, api.CheckResults{
		Masters: map[string]string{
			host.Name: status,
		},
	}, nil
}

// Add installs the component using apt
func (i *dcosInstaller) Add(c api.Component, t api.Target, values map[string]interface{}) (bool, api.AddResults, error) {
	clusterTarget, ok := t.(*ClusterTarget)
	if !ok {
		return false, api.AddResults{}, fmt.Errorf("target isn't a cluster")
	}
	specs := c.Specs()
	_, _, _, err := validateClusterTargets(specs)
	if err != nil {
		return false, api.AddResults{}, err
	}

	if !specs.IsSet("component.installing.dcos.install") {
		msg := `syntax error in component '%s' specification file (%s):
				no key 'component.installing.dcos.install' found`
		return false, api.AddResults{}, fmt.Errorf(msg, c.DisplayName(), c.FullFileName())
	}
	addScript := specs.GetString("component.installing.dcos.install")
	if strings.TrimSpace(addScript) == "" {
		msg := `syntax error in component '%s' specification file (%s):
				key 'component.installing.dcos.install' is empty`
		return false, api.AddResults{}, fmt.Errorf(msg, c.DisplayName(), c.FullFileName())
	}

	cluster := clusterTarget.cluster
	values["reserved_Name"] = c.ShortFileName()
	values["reserved_Content"] = addScript
	values["reserved_Action"] = "install"
	values["MasterIDs"] = cluster.ListMasterIDs()
	values["MasterIPs"] = cluster.ListMasterIPs()
	//values["DomainName"] = cluster.GetConfig().DomainName
	values["dcos"] = dcosCli

	hostID, err := cluster.FindAvailableMaster()
	if err != nil {
		return false, api.AddResults{}, err
	}
	broker := brokerclient.New()
	host, err := broker.Host.Inspect(hostID, brokerclient.DefaultTimeout)
	if err != nil {
		return false, api.AddResults{}, err
	}
	cmdStr, err := realizeScript(values)
	if err != nil {
		return false, api.AddResults{}, err
	}
	filename := fmt.Sprintf("/var/tmp/%s_install.sh", c.ShortFileName())
	err = uploadStringToTargetFile(cmdStr, host, filename)
	if err != nil {
		return false, api.AddResults{}, err
	}
	cmd := fmt.Sprintf("sudo bash %s; rc=$?; sudo rm -f %s; exit $rc", filename, filename)
	duration := specs.GetInt("component.installing.dcos.duration")
	if duration == 0 {
		duration = 5
	}
	retcode, _, _, err := broker.Ssh.Run(hostID, cmd, time.Duration(duration)*time.Minute)
	if err != nil {
		return false, api.AddResults{}, err
	}
	var status error
	ok = retcode == 0
	if !ok {
		status = fmt.Errorf("install script for component '%s' failed, retcode=%d", c.DisplayName(), retcode)
	}
	return ok, api.AddResults{
		Masters: map[string]error{
			host.Name: status,
		},
	}, nil
}

// Remove uninstalls the component using the RemoveScript script
// usage: ok, results, err := i.Remove(c, t)
// - if err != nil, the removal wasn't submitted successfully and err contains why
// - if err == nil and ok ==true, removal wa submitted and succeeded
// - if err == nil and ok == false, removal was submitted successfully but failed, results contain reasons
//   of failures on what parts
func (i *dcosInstaller) Remove(c api.Component, t api.Target) (bool, api.RemoveResults, error) {
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

	if !specs.IsSet("component.installing.dcos.uninstall") {
		msg := `syntax error in component '%s' specification file (%s):
				no key 'component.installing.dcos.uninstall' found`
		return false, api.RemoveResults{}, fmt.Errorf(msg, c.DisplayName(), c.FullFileName())
	}
	removeScript := specs.GetString("component.installing.dcos.uninstall")
	if strings.TrimSpace(removeScript) == "" {
		msg := `syntax error in component '%s' specification file (%s):
				key 'component.installing.dcos.uninstall' is empty`
		return false, api.RemoveResults{}, fmt.Errorf(msg, c.DisplayName(), c.FullFileName())
	}

	cluster := specializedTarget.cluster
	values := map[string]interface{}{
		"reserved_Name":    c.ShortFileName(),
		"reserved_Content": removeScript,
		"reserved_Action":  "uninstall",
		"MasterIDs":        cluster.ListMasterIDs(),
		"MasterIPs":        cluster.ListMasterIPs(),
		//"DomainName": cluster.GetConfig().DomainName,
		"dcos": dcosCli,
	}
	hostID, err := cluster.FindAvailableMaster()
	if err != nil {
		return false, api.RemoveResults{}, err
	}
	broker := brokerclient.New()
	host, err := broker.Host.Inspect(hostID, brokerclient.DefaultTimeout)
	if err != nil {
		return false, api.RemoveResults{}, err
	}
	cmdStr, err := realizeScript(values)
	if err != nil {
		return false, api.RemoveResults{}, err
	}
	filename := fmt.Sprintf("/var/tmp/%s_uninstall.sh", c.ShortFileName())
	err = uploadStringToTargetFile(cmdStr, host, filename)
	if err != nil {
		return false, api.RemoveResults{}, err
	}
	cmd := fmt.Sprintf("sudo bash %s; rc=$?; sudo rm -f %s; exit $rc", filename, filename)
	duration := specs.GetInt("component.installing.dcos.duration")
	if duration == 0 {
		duration = 5
	}

	retcode, _, _, err := broker.Ssh.Run(hostID, cmd, time.Duration(duration)*time.Minute)
	if err != nil {
		return false, api.RemoveResults{}, err
	}
	var status error
	ok = retcode == 0
	if !ok {
		status = fmt.Errorf("uninstall script for component '%s' failed, retcode=%d", c.DisplayName(), retcode)
	}
	return ok, api.RemoveResults{
		AddResults: api.AddResults{
			Masters: map[string]error{
				host.Name: status,
			},
		},
	}, nil
}

// NewDcosInstaller creates a new instance of Installer using DCOS
func NewDcosInstaller() api.Installer {
	return &dcosInstaller{}
}
