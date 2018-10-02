package install

import (
	"fmt"
	"log"

	"github.com/CS-SI/SafeScale/deploy/install/enums/Action"
	"github.com/CS-SI/SafeScale/deploy/install/enums/Method"
)

// bashInstaller is an installer using script to add and remove a component
type bashInstaller struct{}

func (i *bashInstaller) GetName() string {
	return "script"
}

// Check checks if the component is installed, using the check script in Specs
func (i *bashInstaller) Check(c *Component, t Target, v Variables) (Results, error) {
	specs := c.Specs()
	yamlKey := "component.install.bash.check"
	if !specs.IsSet(yamlKey) {
		msg := `syntax error in component '%s' specification file (%s): no key '%s' found`
		return nil, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename(), yamlKey)
	}

	_, clusterTarget, _ := determineContext(t)
	if clusterTarget != nil {
		return i.checkOnCluster(c, t, v)
	}
	return i.checkOnHost(c, t, v)
}

func (i *bashInstaller) checkOnHost(c *Component, t Target, v Variables) (Results, error) {
	worker, err := newWorker(c, t, Method.Bash, Action.Check, nil)
	if err != nil {
		return nil, err
	}
	hostTarget, _, nodeTarget := determineContext(t)
	if hostTarget == nil && nodeTarget == nil {
		return nil, fmt.Errorf("invalid target")
	}
	err = worker.CanProceed()
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	return worker.Proceed(v)
}

func (i *bashInstaller) checkOnCluster(c *Component, t Target, v Variables) (Results, error) {
	worker, err := newWorker(c, t, Method.Bash, Action.Check, nil)
	if err != nil {
		return nil, err
	}

	err = worker.CanProceed()
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	v["kubectl"] = kubectlCli

	return worker.Proceed(v)
}

// Add installs the component using the install script in Specs
// 'values' contains the values associated with parameters as defined in specification file
func (i *bashInstaller) Add(c *Component, t Target, v Variables) (Results, error) {
	specs := c.Specs()
	// If component is installed, do nothing but responds with success
	results, err := i.Check(c, t, v)
	if err != nil {
		return nil, fmt.Errorf("component '%s' check failed: %s", c.DisplayName(), err.Error())
	}
	if results.Successful() {
		log.Printf("Component '%s' is already installed\n", c.DisplayName())
		return results, nil
	}

	// Inits implicit parameters
	setImplicitParameters(t, v)

	// Checks required parameters have value
	err = checkParameters(c, v)
	if err != nil {
		return nil, err
	}

	// Determining if install script is defined in specification file
	if !specs.IsSet("component.install.bash.add") {
		msg := `syntax error in component '%s' specification file (%s):
				no key 'component.install.bash.add' found`
		return nil, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}

	// Installs requirements if there are any
	err = installRequirements(c, t, v)
	if err != nil {
		return nil, fmt.Errorf("failed to install requirements: %s", err.Error())
	}

	_, clusterTarget, _ := determineContext(t)
	if clusterTarget != nil {
		return i.addOnCluster(c, t, v)
	}
	return i.addOnHost(c, t, v)
}

// addOnHost installs a component on an host
// If install fails return err; results may not be nil and will then contains the details of execution
func (i *bashInstaller) addOnHost(c *Component, t Target, v Variables) (Results, error) {
	worker, err := newWorker(c, t, Method.Bash, Action.Add, nil)
	if err != nil {
		return nil, err
	}
	err = worker.CanProceed()
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	if _, ok := v["Username"]; !ok {
		v["Username"] = "gpac"
	}

	return worker.Proceed(v)
}

// addOnCluster installs a component on a cluster
func (i *bashInstaller) addOnCluster(c *Component, t Target, v Variables) (Results, error) {
	worker, err := newWorker(c, t, Method.Bash, Action.Add, nil)
	if err != nil {
		return nil, err
	}
	err = worker.CanProceed()
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	//v["DomainName"] = cluster.GetConfig().DomainName
	//v["dcos"] = dcosCli
	v["kubectl"] = kubectlCli
	//v["options"] = ""

	return worker.Proceed(v)
}

// Remove uninstalls the component
func (i *bashInstaller) Remove(c *Component, t Target, v Variables) (Results, error) {
	specs := c.Specs()
	if !specs.IsSet("component.install.bash.remove") {
		msg := `syntax error in component '%s' specification file (%s):
				no key 'component.install.bash.remove' found`
		return nil, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}
	// Inits implicit parameters
	setImplicitParameters(t, v)

	// Checks required parameters have value
	err := checkParameters(c, v)
	if err != nil {
		return nil, err
	}

	_, clusterTarget, _ := determineContext(t)
	if clusterTarget != nil {
		return i.removeFromCluster(c, t, v)
	}
	return i.removeFromHost(c, t, v)
}

// removeFromHost uninstalls a component from a host
func (i *bashInstaller) removeFromHost(c *Component, t Target, v Variables) (Results, error) {
	worker, err := newWorker(c, t, Method.Bash, Action.Remove, nil)
	if err != nil {
		return nil, err
	}
	err = worker.CanProceed()
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	//v["DomainName"] = cluster.GetConfig().DomainName
	//v["dcos"] = dcosCli
	v["kubectl"] = kubectlCli
	//v["options"] = ""

	return worker.Proceed(v)
}

// removeFromCluster uninstalled a component from a cluster
func (i *bashInstaller) removeFromCluster(c *Component, t Target, v Variables) (Results, error) {
	worker, err := newWorker(c, t, Method.Bash, Action.Remove, nil)
	if err != nil {
		return nil, err
	}
	err = worker.CanProceed()
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	//v["DomainName"] = cluster.GetConfig().DomainName
	v["kubectl"] = kubectlCli

	return worker.Proceed(v)
}

// NewBashInstaller creates a new instance of Installer using script
func NewBashInstaller() Installer {
	return &bashInstaller{}
}
