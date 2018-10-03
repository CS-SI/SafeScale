package install

import (
	"fmt"
	"log"

	"github.com/CS-SI/SafeScale/deploy/install/enums/Action"
	"github.com/CS-SI/SafeScale/deploy/install/enums/Method"
)

const (
	dcosCli     = "sudo -u cladm -i dcos"
	kubectlCli  = "sudo -u cladm -i kubectl"
	marathonCli = "sudo -u cladm -i marathon"
)

// dcosInstaller is an installer using script to add and remove a component
type dcosInstaller struct{}

func (i *dcosInstaller) GetName() string {
	return "dcos"
}

// Check checks if the component is installed
func (i *dcosInstaller) Check(c *Component, t Target, v Variables) (Results, error) {
	worker, err := newWorker(c, t, Method.DCOS, Action.Add, nil)
	if err != nil {
		return nil, err
	}
	err = worker.CanProceed()
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	// Inits implicit parameters
	setImplicitParameters(t, v)

	// Checks required parameters have value
	err = checkParameters(c, v)
	if err != nil {
		return nil, err
	}

	// Replaces variables in normalized script
	//v["DomainName"] = cluster.GetConfig().DomainName
	v["dcos"] = dcosCli
	v["kubectl"] = kubectlCli
	v["options"] = ""

	return worker.Proceed(v)
}

// Add installs the component in a DCOS cluster
func (i *dcosInstaller) Add(c *Component, t Target, v Variables) (Results, error) {
	worker, err := newWorker(c, t, Method.DCOS, Action.Add, nil)
	if err != nil {
		return nil, err
	}
	err = worker.CanProceed()
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	// Installs requirements if there are any
	err = installRequirements(c, t, v)
	if err != nil {
		return nil, fmt.Errorf("failed to install requirements: %s", err.Error())
	}

	// Inits implicit parameters
	setImplicitParameters(t, v)

	// Checks required parameters have value
	err = checkParameters(c, v)
	if err != nil {
		return nil, err
	}

	// Replaces variables in normalized script
	//v["DomainName"] = cluster.GetConfig().DomainName
	v["dcos"] = dcosCli
	v["kubectl"] = kubectlCli
	v["options"] = ""

	return worker.Proceed(v)
}

// Remove uninstalls the component using the RemoveScript script
// usage: ok, results, err := i.Remove(c, t)
// - if err != nil, the removal wasn't submitted successfully and err contains why
// - if err == nil and ok ==true, removal wa submitted and succeeded
// - if err == nil and ok == false, removal was submitted successfully but failed, results contain reasons
//   of failures on what parts
func (i *dcosInstaller) Remove(c *Component, t Target, v Variables) (Results, error) {

	worker, err := newWorker(c, t, Method.DCOS, Action.Remove, nil)
	if err != nil {
		return nil, err
	}
	err = worker.CanProceed()
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	// Inits implicit parameters
	setImplicitParameters(t, v)

	// Checks required parameters have value
	err = checkParameters(c, v)
	if err != nil {
		return nil, err
	}

	// Replaces variables in normalized script
	//v["DomainName"] = cluster.GetConfig().DomainName
	v["dcos"] = dcosCli
	v["kubectl"] = kubectlCli
	v["options"] = ""

	return worker.Proceed(v)
}

// NewDcosInstaller creates a new instance of Installer using DCOS
func NewDcosInstaller() Installer {
	return &dcosInstaller{}
}
