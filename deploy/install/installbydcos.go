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

// dcosInstaller is an installer using script to add and remove a feature
type dcosInstaller struct{}

func (i *dcosInstaller) GetName() string {
	return "dcos"
}

// Check checks if the feature is installed
func (i *dcosInstaller) Check(c *Feature, t Target, v Variables, s Settings) (Results, error) {
	worker, err := newWorker(c, t, Method.DCOS, Action.Check, nil)
	if err != nil {
		return nil, err
	}
	err = worker.CanProceed(s)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	// Replaces variables in normalized script
	//v["DomainName"] = cluster.GetConfig().DomainName
	//	v["dcos"] = dcosCli
	//	v["kubectl"] = kubectlCli
	v["options"] = ""

	return worker.Proceed(v, s)
}

// Add installs the feature in a DCOS cluster
func (i *dcosInstaller) Add(c *Feature, t Target, v Variables, s Settings) (Results, error) {
	worker, err := newWorker(c, t, Method.DCOS, Action.Add, nil)
	if err != nil {
		return nil, err
	}
	err = worker.CanProceed(s)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	// Installs requirements if there are any
	if !s.SkipFeatureRequirements {
		err = installRequirements(c, t, v, s)
		if err != nil {
			return nil, fmt.Errorf("failed to install requirements: %s", err.Error())
		}
	}

	// Replaces variables in normalized script
	//v["DomainName"] = cluster.GetConfig().DomainName
	//v["dcos"] = dcosCli
	//v["kubectl"] = kubectlCli
	v["options"] = ""

	return worker.Proceed(v, s)
}

// Remove uninstalls the feature using the RemoveScript script
// usage: ok, results, err := i.Remove(c, t)
// - if err != nil, the removal wasn't submitted successfully and err contains why
// - if err == nil and ok ==true, removal wa submitted and succeeded
// - if err == nil and ok == false, removal was submitted successfully but failed, results contain reasons
//   of failures on what parts
func (i *dcosInstaller) Remove(c *Feature, t Target, v Variables, s Settings) (Results, error) {

	worker, err := newWorker(c, t, Method.DCOS, Action.Remove, nil)
	if err != nil {
		return nil, err
	}
	err = worker.CanProceed(s)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	// Replaces variables in normalized script
	//v["DomainName"] = cluster.GetConfig().DomainName
	//	v["dcos"] = dcosCli
	//	v["kubectl"] = kubectlCli
	v["options"] = ""

	return worker.Proceed(v, s)
}

// NewDcosInstaller creates a new instance of Installer using DCOS
func NewDcosInstaller() Installer {
	return &dcosInstaller{}
}
