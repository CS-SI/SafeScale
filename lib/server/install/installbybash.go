package install

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/install/enums/Action"
	"github.com/CS-SI/SafeScale/lib/server/install/enums/Method"
)

// bashInstaller is an installer using script to add and remove a feature
type bashInstaller struct{}

func (i *bashInstaller) GetName() string {
	return "script"
}

// Check checks if the feature is installed, using the check script in Specs
func (i *bashInstaller) Check(f *Feature, t Target, v Variables, s Settings) (Results, error) {
	yamlKey := "feature.install.bash.check"
	if !f.specs.IsSet(yamlKey) {
		msg := `syntax error in feature '%s' specification file (%s): no key '%s' found`
		return nil, fmt.Errorf(msg, f.DisplayName(), f.DisplayFilename(), yamlKey)
	}

	worker, err := newWorker(f, t, Method.Bash, Action.Check, nil)
	if err != nil {
		return nil, err
	}

	err = worker.CanProceed(s)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	return worker.Proceed(v, s)
}

// Add installs the feature using the install script in Specs
// 'values' contains the values associated with parameters as defined in specification file
func (i *bashInstaller) Add(f *Feature, t Target, v Variables, s Settings) (Results, error) {
	// Determining if install script is defined in specification file
	if !f.specs.IsSet("feature.install.bash.add") {
		msg := `syntax error in feature '%s' specification file (%s):
				no key 'feature.install.bash.add' found`
		return nil, fmt.Errorf(msg, f.DisplayName(), f.DisplayFilename())
	}

	worker, err := newWorker(f, t, Method.Bash, Action.Add, nil)
	if err != nil {
		return nil, err
	}
	err = worker.CanProceed(s)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	if !worker.ConcernsCluster() {
		if _, ok := v["Username"]; !ok {
			v["Username"] = "safescale"
		}
	}
	return worker.Proceed(v, s)
}

// Remove uninstalls the feature
func (i *bashInstaller) Remove(f *Feature, t Target, v Variables, s Settings) (Results, error) {
	if !f.specs.IsSet("feature.install.bash.remove") {
		msg := `syntax error in feature '%s' specification file (%s):
				no key 'feature.install.bash.remove' found`
		return nil, fmt.Errorf(msg, f.DisplayName(), f.DisplayFilename())
	}

	worker, err := newWorker(f, t, Method.Bash, Action.Remove, nil)
	if err != nil {
		return nil, err
	}
	err = worker.CanProceed(s)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	_, clusterTarget, _ := determineContext(t)
	if clusterTarget == nil {
		if _, ok := v["Username"]; !ok {
			v["Username"] = "safescale"
		}
	}
	return worker.Proceed(v, s)
}

// NewBashInstaller creates a new instance of Installer using script
func NewBashInstaller() Installer {
	return &bashInstaller{}
}
