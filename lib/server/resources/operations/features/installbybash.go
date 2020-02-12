package features

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installaction"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/lib/utils/data"
)

// bashInstaller is an installer using script to add and remove a feature
type bashInstaller struct{}

func (i *bashInstaller) GetName() string {
	return "script"
}

// Check checks if the feature is installed, using the check script in Specs
func (i *bashInstaller) Check(f resources.Feature, t resources.Targetable, v data.Map, s resources.FeatureSettings) (resources.Results, error) {
	yamlKey := "feature.install.bash.check"
	if !f.Specs().IsSet(yamlKey) {
		msg := `syntax error in feature '%s' specification file (%s): no key '%s' found`
		return nil, fmt.Errorf(msg, f.Name(), f.DisplayFilename(), yamlKey)
	}

	worker, err := newWorker(f, t, installmethod.Bash, installaction.Check, nil)
	if err != nil {
		return nil, err
	}

	err = worker.CanProceed(s)
	if err != nil {
		logrus.Println(err.Error())
		return nil, err
	}
	return worker.Proceed(v, s)
}

// Add installs the feature using the install script in Specs
// 'values' contains the values associated with parameters as defined in specification file
func (i *bashInstaller) Add(f resources.Feature, t resources.Targetable, v data.Map, s resources.FeatureSettings) (resources.Results, error) {
	// Determining if install script is defined in specification file
	if !f.Specs().IsSet("feature.install.bash.add") {
		msg := `syntax error in feature '%s' specification file (%s):
				no key 'feature.install.bash.add' found`
		return nil, fmt.Errorf(msg, f.Name(), f.DisplayFilename())
	}

	worker, err := newWorker(f, t, installmethod.Bash, installaction.Add, nil)
	if err != nil {
		return nil, err
	}
	err = worker.CanProceed(s)
	if err != nil {
		logrus.Println(err.Error())
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
func (i *bashInstaller) Remove(f resources.Feature, t resources.Targetable, v data.Map, s resources.FeatureSettings) (resources.Results, error) {
	if !f.Specs().IsSet("feature.install.bash.remove") {
		msg := `syntax error in feature '%s' specification file (%s):
				no key 'feature.install.bash.remove' found`
		return nil, fmt.Errorf(msg, f.Name(), f.DisplayFilename())
	}

	worker, err := newWorker(f, t, installmethod.Bash, installaction.Remove, nil)
	if err != nil {
		return nil, err
	}
	err = worker.CanProceed(s)
	if err != nil {
		logrus.Println(err.Error())
		return nil, err
	}

	if t.TargetType() != featuretargettype.CLUSTER {
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
