package install

import (
	"fmt"
	"log"

	"github.com/CS-SI/SafeScale/deploy/install/enums/Action"
	"github.com/CS-SI/SafeScale/deploy/install/enums/Method"
)

// bashInstaller is an installer using script to add and remove a feature
type bashInstaller struct{}

func (i *bashInstaller) GetName() string {
	return "script"
}

// Check checks if the feature is installed, using the check script in Specs
func (i *bashInstaller) Check(c *Feature, t Target, v Variables, s Settings) (Results, error) {
	specs := c.Specs()
	yamlKey := "feature.install.bash.check"
	if !specs.IsSet(yamlKey) {
		msg := `syntax error in feature '%s' specification file (%s): no key '%s' found`
		return nil, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename(), yamlKey)
	}

	worker, err := newWorker(c, t, Method.Bash, Action.Check, nil)
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
func (i *bashInstaller) Add(c *Feature, t Target, v Variables, s Settings) (Results, error) {
	specs := c.Specs()
	if !s.SkipCheck {
		// If feature is installed, do nothing but responds with success
		results, err := i.Check(c, t, v, s)
		if err != nil {
			return nil, fmt.Errorf("feature check failed: %s", err.Error())
		}
		if results.Successful() {
			//log.Printf("Feature '%s' is already installed\n", c.DisplayName())
			return results, nil
		}
	}

	// Determining if install script is defined in specification file
	if !specs.IsSet("feature.install.bash.add") {
		msg := `syntax error in feature '%s' specification file (%s):
				no key 'feature.install.bash.add' found`
		return nil, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}

	// Installs requirements if there are any
	if !s.SkipFeatureRequirements {
		err := installRequirements(c, t, v, s)
		if err != nil {
			return nil, fmt.Errorf("failed to install requirements: %s", err.Error())
		}
	}

	worker, err := newWorker(c, t, Method.Bash, Action.Add, nil)
	if err != nil {
		return nil, err
	}
	err = worker.CanProceed(s)
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}
	if !worker.ConcernCluster() {
		if _, ok := v["Username"]; !ok {
			v["Username"] = "gpac"
		}
	}
	return worker.Proceed(v, s)
}

// Remove uninstalls the feature
func (i *bashInstaller) Remove(c *Feature, t Target, v Variables, s Settings) (Results, error) {
	specs := c.Specs()
	if !specs.IsSet("feature.install.bash.remove") {
		msg := `syntax error in feature '%s' specification file (%s):
				no key 'feature.install.bash.remove' found`
		return nil, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename())
	}

	worker, err := newWorker(c, t, Method.Bash, Action.Remove, nil)
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
			v["Username"] = "gpac"
		}
	}
	return worker.Proceed(v, s)
}

// NewBashInstaller creates a new instance of Installer using script
func NewBashInstaller() Installer {
	return &bashInstaller{}
}
