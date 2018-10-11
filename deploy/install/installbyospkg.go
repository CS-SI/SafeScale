package install

import (
	"fmt"
	"log"

	"github.com/CS-SI/SafeScale/deploy/install/enums/Action"
	"github.com/CS-SI/SafeScale/deploy/install/enums/Method"
)

// genericPackager is an object implementing the OS package management
// It handles package management on single host or entire cluster
type genericPackager struct {
	name          string
	checkCommand  alterCommandCB
	addCommand    alterCommandCB
	removeCommand alterCommandCB
}

// GetName returns the name of the installer (ex: apt, yum, dnf)
func (g *genericPackager) GetName() string {
	return g.name
}

// Check checks if the feature is installed
func (g *genericPackager) Check(c *Feature, t Target, v Variables, s Settings) (Results, error) {
	specs := c.Specs()
	yamlKey := "feature.install." + g.name + ".check"
	if !specs.IsSet(yamlKey) {
		msg := `syntax error in feature '%s' specification file (%s):
				no key '%s' found`
		return nil, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename(), yamlKey)
	}

	worker, err := newWorker(c, t, Method.Bash, Action.Check, g.checkCommand)
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

// Add installs the feature using apt
func (g *genericPackager) Add(c *Feature, t Target, v Variables, s Settings) (Results, error) {
	yamlKey := "feature.install." + g.name + ".add"
	if !c.Specs().IsSet(yamlKey) {
		msg := `syntax error in feature '%s' specification file (%s):
				no key '%s' found`
		return nil, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename(), yamlKey)
	}

	// Installs requirements if there are any
	if !s.SkipFeatureRequirements {
		err := installRequirements(c, t, v, s)
		if err != nil {
			return nil, fmt.Errorf("failed to install requirements: %s", err.Error())
		}
	}

	worker, err := newWorker(c, t, Method.Bash, Action.Add, g.addCommand)
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

// Remove uninstalls the feature using the RemoveScript script
func (g *genericPackager) Remove(c *Feature, t Target, v Variables, s Settings) (Results, error) {
	yamlKey := "feature.install." + g.name + ".remove"
	if !c.Specs().IsSet(yamlKey) {
		msg := `syntax error in feature '%s' specification file (%s):
				no key '%s' found`
		return nil, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename(), yamlKey)
	}

	worker, err := newWorker(c, t, Method.Bash, Action.Remove, g.removeCommand)
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

// aptInstaller is an installer using script to add and remove a feature
type aptInstaller struct {
	genericPackager
}

// NewAptInstaller creates a new instance of Installer using script
func NewAptInstaller() Installer {
	return &aptInstaller{
		genericPackager: genericPackager{
			name: "apt",
			checkCommand: func(pkg string) string {
				return fmt.Sprintf("sudo dpkg-query -s '%s' &>/dev/null", pkg)
			},
			addCommand: func(pkg string) string {
				return fmt.Sprintf("sudo apt-get install -y '%s'", pkg)
			},
			removeCommand: func(pkg string) string {
				return fmt.Sprintf("sudo apt-get remove -y '%s'", pkg)
			},
		},
	}
}

// yumInstaller is an installer using yum to add and remove a feature
type yumInstaller struct {
	genericPackager
}

// NewYumInstaller creates a new instance of Installer using script
func NewYumInstaller() Installer {
	return &yumInstaller{
		genericPackager: genericPackager{
			name: "yum",
			checkCommand: func(pkg string) string {
				return fmt.Sprintf("sudo rpm -q %s &>/dev/null", pkg)
			},
			addCommand: func(pkg string) string {
				return fmt.Sprintf("sudo yum install -y %s", pkg)
			},
			removeCommand: func(pkg string) string {
				return fmt.Sprintf("sudo yum remove -y %s", pkg)
			},
		},
	}
}

// dnfInstaller is an installer using yum to add and remove a feature
type dnfInstaller struct {
	genericPackager
}

// NewDnfInstaller creates a new instance of Installer using script
func NewDnfInstaller() Installer {
	return &dnfInstaller{
		genericPackager: genericPackager{
			name: "dnf",
			checkCommand: func(pkg string) string {
				return fmt.Sprintf("sudo dnf list installed %s &>/dev/null", pkg)
			},
			addCommand: func(pkg string) string {
				return fmt.Sprintf("sudo dnf install -y %s", pkg)
			},
			removeCommand: func(pkg string) string {
				return fmt.Sprintf("sudo dnf uninstall -y %s", pkg)
			},
		},
	}
}
