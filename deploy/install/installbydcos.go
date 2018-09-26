package install

import (
	"fmt"
	"log"
	"strings"
	"time"

	pb "github.com/CS-SI/SafeScale/broker"
	brokerclient "github.com/CS-SI/SafeScale/broker/client"

	"github.com/CS-SI/SafeScale/deploy/install/enums/Action"
	"github.com/CS-SI/SafeScale/deploy/install/enums/Method"
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
func (i *dcosInstaller) Check(c *Component, t Target, v Variables) (bool, CheckResults, error) {
	clusterTarget, ok := t.(*ClusterTarget)
	if !ok {
		return false, CheckResults{}, fmt.Errorf("target isn't a cluster")
	}
	cluster := clusterTarget.cluster

	if !validateContextForCluster(c, cluster) {
		msg := fmt.Sprintf("component not permitted on flavor '%s' of cluster '%s'\n", cluster.GetConfig().Flavor.String(), t.Name())
		log.Println(msg)
		return false, CheckResults{}, fmt.Errorf(msg)
	}

	if err := validateClusterSizing(c, cluster); err != nil {
		return false, CheckResults{}, err
	}

	// Note: In special case of DCOS, installation is done on any master available. values returned
	// by validateClusterTargets() are ignored
	specs := c.Specs()
	_, _, _, err := validateClusterTargets(specs)
	if err != nil {
		return false, CheckResults{}, err
	}

	if !specs.IsSet("component.install.dcos.check") {
		msg := `syntax error in component '%s' specification file (%s):
				no key 'component.install.dcos.check' found`
		return false, CheckResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}
	checkScript := specs.GetString("component.install.dcos.check")
	if strings.TrimSpace(checkScript) == "" {
		msg := `syntax error in component '%s' specification file (%s):
				key 'component.install.dcos.check' is empty`
		return false, CheckResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}

	hostID, err := cluster.FindAvailableMaster()
	if err != nil {
		return false, CheckResults{}, err
	}
	broker := brokerclient.New()
	host, err := broker.Host.Inspect(hostID, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		return false, CheckResults{}, err
	}
	cmdStr, err := normalizeScript(Variables{
		"reserved_Name":    c.BaseFilename(),
		"reserved_Content": checkScript,
		"reserved_Action":  "check",
	})
	if err != nil {
		return false, CheckResults{}, err
	}

	// Replaces variables in normalized script
	v["MasterIDs"] = cluster.ListMasterIDs()
	v["MasterIPs"] = cluster.ListMasterIPs()
	//v["DomainName"] = cluster.GetConfig().DomainName
	v["dcos"] = dcosCli
	if _, ok := v["Username"]; !ok {
		v["Username"] = "cladm"
	}
	cmdStr, err = replaceVariablesInString(cmdStr, v)
	if err != nil {
		return false, CheckResults{}, fmt.Errorf("failed to finalize check script: %s", err.Error())
	}

	// Uploads the executes the script
	filename := fmt.Sprintf("/var/tmp/%s_check.sh", c.BaseFilename())
	err = UploadStringToRemoteFile(cmdStr, host, filename, "", "", "u+rw-x,go-rwx")
	if err != nil {
		return false, CheckResults{}, err
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
		return false, CheckResults{}, err
	}
	ok = retcode == 0
	return ok, CheckResults{host.Name: CheckState{Success: true, Present: ok}}, nil
}

type task struct {
	action    string
	component *Component
	hosts     []*pb.Host
	values    map[string]interface{}
	serial    bool
	before    func(*task) error
	run       func(*task, interface{}) error
	after     func(*task) error
}

func (t *task) execute() error {
	defer t.after(t)

	err := t.before(t)
	if err != nil {
		return err
	}
	if t.serial {
		// Loops steps in serial order
		for _, host := range t.hosts {
			t.values["HostIP"] = host.ID
			t.values["Hostname"] = host.Name

			err := t.run(t, host)
			if err != nil {
				return err
			}
		}
	} else {
		// Loops steps in parallels
		for _, host := range t.hosts {
			t.values["HostIP"] = host.ID
			t.values["Hostname"] = host.Name

			err := t.run(t, host)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Add installs the component in a DCOS cluster
func (i *dcosInstaller) Add(c *Component, t Target, v Variables) (bool, AddResults, error) {
	worker, err := NewWorker(c, t, Method.DCOS, Action.Add)
	if err != nil {
		return false, AddResults{}, err
	}
	clusterTarget, ok := t.(*ClusterTarget)
	if !ok {
		return false, AddResults{}, fmt.Errorf("target is not a cluster")
	}
	cluster := clusterTarget.cluster
	if err := validateClusterSizing(c, cluster); err != nil {
		return false, AddResults{}, err
	}

	if !worker.CanProceed() {
		msg := fmt.Sprintf("component can't apply to flavor '%s' of cluster '%s'\n", cluster.GetConfig().Flavor.String(), t.Name())
		log.Println(msg)
		return false, AddResults{}, fmt.Errorf(msg)
	}

	//specs := c.Specs()
	// _, _, _, err := validateClusterTargets(specs)
	// if err != nil {
	// 	return false, AddResults{}, err
	// }

	// Replaces variables in normalized script
	v["MasterIDs"] = cluster.ListMasterIDs()
	v["MasterIPs"] = cluster.ListMasterIPs()
	//v["DomainName"] = cluster.GetConfig().DomainName
	v["dcos"] = dcosCli
	v["kubectl"] = kubectlCli
	v["options"] = ""
	if _, ok := v["Username"]; !ok {
		v["Username"] = "cladm"
	}

	results, err := worker.Proceed(v)
	if err != nil {
		return false, results, err
	}

	return true, results, err
}

// Remove uninstalls the component using the RemoveScript script
// usage: ok, results, err := i.Remove(c, t)
// - if err != nil, the removal wasn't submitted successfully and err contains why
// - if err == nil and ok ==true, removal wa submitted and succeeded
// - if err == nil and ok == false, removal was submitted successfully but failed, results contain reasons
//   of failures on what parts
func (i *dcosInstaller) Remove(c *Component, t Target, v Variables) (bool, RemoveResults, error) {
	clusterTarget, ok := t.(*ClusterTarget)
	if !ok {
		return false, RemoveResults{}, fmt.Errorf("target isn't a cluster")
	}
	cluster := clusterTarget.cluster

	if !validateContextForCluster(c, cluster) {
		msg := fmt.Sprintf("component not permitted on flavor '%s' of cluster '%s'\n", cluster.GetConfig().Flavor.String(), t.Name())
		log.Println(msg)
		return false, RemoveResults{}, fmt.Errorf(msg)
	}

	specs := c.Specs()
	_, _, _, err := validateClusterTargets(specs)
	if err != nil {
		return false, RemoveResults{}, err
	}
	// Note: In special case of DCOS, removal is done on any master available. values returned
	// by clusterTargets() are ignored

	if !specs.IsSet("component.install.dcos.remove") {
		msg := `syntax error in component '%s' specification file (%s):
				no key 'component.install.dcos.remove' found`
		return false, RemoveResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}
	removeScript := specs.GetString("component.install.dcos.remove")
	if strings.TrimSpace(removeScript) == "" {
		msg := `syntax error in component '%s' specification file (%s):
				key 'component.install.dcos.remove' is empty`
		return false, RemoveResults{}, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}

	hostID, err := cluster.FindAvailableMaster()
	if err != nil {
		return false, RemoveResults{}, err
	}
	broker := brokerclient.New()
	host, err := broker.Host.Inspect(hostID, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		return false, RemoveResults{}, err
	}

	// Normalizes script
	cmdStr, err := normalizeScript(Variables{
		"reserved_Name":    c.BaseFilename(),
		"reserved_Content": removeScript,
		"reserved_Action":  "remove",
	})
	if err != nil {
		return false, RemoveResults{}, err
	}

	// Replaces variables in normalized script
	v["MasterIDs"] = cluster.ListMasterIDs()
	v["MasterIPs"] = cluster.ListMasterIPs()
	//v["DomainName"] = cluster.GetConfig().DomainName
	v["dcos"] = dcosCli
	if _, ok := v["Username"]; !ok {
		v["Username"] = "cladm"
	}
	cmdStr, err = replaceVariablesInString(cmdStr, v)
	if err != nil {
		return false, RemoveResults{}, fmt.Errorf("failed to finalize install script: %s", err.Error())
	}

	// Uploads then executes script
	filename := fmt.Sprintf("/var/tmp/%s_remove.sh", c.BaseFilename())
	err = UploadStringToRemoteFile(cmdStr, host, filename, "", "", "")
	if err != nil {
		return false, RemoveResults{}, err
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
		return false, RemoveResults{}, err
	}
	ok = retcode == 0
	if !ok {
		err = fmt.Errorf("uninstall script failed (retcode=%d)", retcode)
	}
	return ok, RemoveResults{map[string]stepErrors{host.Name: stepErrors{"__error__": err}}}, err
}

// NewDcosInstaller creates a new instance of Installer using DCOS
func NewDcosInstaller() Installer {
	return &dcosInstaller{}
}
