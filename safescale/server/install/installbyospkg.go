package install

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/safescale/server/install/enums/Action"
	"github.com/CS-SI/SafeScale/safescale/server/install/enums/Method"
)

// genericPackager is an object implementing the OS package management
// It handles package management on single host or entire cluster
type genericPackager struct {
	keyword       string
	method        Method.Enum
	checkCommand  alterCommandCB
	addCommand    alterCommandCB
	removeCommand alterCommandCB
}

// Check checks if the feature is installed
func (g *genericPackager) Check(f *Feature, t Target, v Variables, s Settings) (Results, error) {
	yamlKey := "feature.install." + g.keyword + ".check"
	if !f.specs.IsSet(yamlKey) {
		msg := `syntax error in feature '%s' specification file (%s):
				no key '%s' found`
		return nil, fmt.Errorf(msg, f.DisplayName(), f.DisplayFilename(), yamlKey)
	}

	worker, err := newWorker(f, t, g.method, Action.Check, g.checkCommand)
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
func (g *genericPackager) Add(f *Feature, t Target, v Variables, s Settings) (Results, error) {
	yamlKey := "feature.install." + g.keyword + ".add"
	if !f.specs.IsSet(yamlKey) {
		msg := `syntax error in feature '%s' specification file (%s):
				no key '%s' found`
		return nil, fmt.Errorf(msg, f.DisplayName(), f.DisplayFilename(), yamlKey)
	}

	worker, err := newWorker(f, t, g.method, Action.Add, g.addCommand)
	if err != nil {
		log.Println(err.Error())
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
func (g *genericPackager) Remove(f *Feature, t Target, v Variables, s Settings) (Results, error) {
	yamlKey := "feature.install." + g.keyword + ".remove"
	if !f.specs.IsSet(yamlKey) {
		msg := `syntax error in feature '%s' specification file (%s):
				no key '%s' found`
		return nil, fmt.Errorf(msg, f.DisplayName(), f.DisplayFilename(), yamlKey)
	}

	worker, err := newWorker(f, t, g.method, Action.Remove, g.removeCommand)
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
			keyword: strings.ToLower(Method.Apt.String()),
			method:  Method.Apt,
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
			keyword: strings.ToLower(Method.Yum.String()),
			method:  Method.Yum,
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
			keyword: strings.ToLower(Method.Dnf.String()),
			method:  Method.Dnf,
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
