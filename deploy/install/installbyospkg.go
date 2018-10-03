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

// Check checks if the component is installed
func (g *genericPackager) Check(c *Component, t Target, v Variables) (Results, error) {
	specs := c.Specs()
	yamlKey := "component.install." + g.name + ".check"
	if !specs.IsSet(yamlKey) {
		msg := `syntax error in component '%s' specification file (%s):
				no key '%s' found`
		return nil, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename(), yamlKey)
	}

	// Inits implicit parameters
	setImplicitParameters(t, v)

	// Checks required parameters have value
	err := checkParameters(c, v)
	if err != nil {
		return nil, err
	}

	worker, err := newWorker(c, t, Method.Bash, Action.Check, g.checkCommand)
	if err != nil {
		return nil, err
	}
	err = worker.CanProceed()
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	return worker.Proceed(v)
}

// Add installs the component using apt
func (g *genericPackager) Add(c *Component, t Target, v Variables) (Results, error) {
	yamlKey := "component.install." + g.name + ".add"
	if !c.Specs().IsSet(yamlKey) {
		msg := `syntax error in component '%s' specification file (%s):
				no key '%s' found`
		return nil, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename(), yamlKey)
	}

	// Inits implicit parameters
	setImplicitParameters(t, v)

	// Checks required parameters have value
	err := checkParameters(c, v)
	if err != nil {
		return nil, err
	}

	worker, err := newWorker(c, t, Method.Bash, Action.Add, g.addCommand)
	if err != nil {
		return nil, err
	}
	err = worker.CanProceed()
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	return worker.Proceed(v)
}

// Remove uninstalls the component using the RemoveScript script
func (g *genericPackager) Remove(c *Component, t Target, v Variables) (Results, error) {
	yamlKey := "component.install." + g.name + ".remove"
	if !c.Specs().IsSet(yamlKey) {
		msg := `syntax error in component '%s' specification file (%s):
				no key '%s' found`
		return nil, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename(), yamlKey)
	}

	// Inits implicit parameters
	setImplicitParameters(t, v)

	// Checks required parameters have value
	err := checkParameters(c, v)
	if err != nil {
		return nil, err
	}

	worker, err := newWorker(c, t, Method.Bash, Action.Remove, g.removeCommand)
	if err != nil {
		return nil, err
	}
	err = worker.CanProceed()
	if err != nil {
		log.Println(err.Error())
		return nil, err
	}

	return worker.Proceed(v)
}

// // findConcernedMaster determines from all masters which one has the component installed
// func findConcernedMaster(cluster clusterapi.Cluster, c *Component) (string, error) {
// 	// metadata not yet implemented for components, so assuming the concerned master is
// 	// the available one
// 	return cluster.FindAvailableMaster()
// 	//for _, m := range cluster.ListMasterIDs() {
// 	//}
// }

// // findConcernedNode determines from all nodes which one has the component installed
// func findConcernedNode(cluster clusterapi.Cluster, c *Component, public bool) (string, error) {
// 	// metadata not yet implemented for components, so assuming the concerned node is
// 	// the first one
// 	list := cluster.ListNodeIDs(public)
// 	if len(list) > 0 {
// 		return list[0], nil
// 	}
// 	return "", fmt.Errorf("no node found")
// 	//for _, m := range cluster.ListNodeIDs(public) {
// 	//}
// }

// aptInstaller is an installer using script to add and remove a component
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

// yumInstaller is an installer using yum to add and remove a component
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

// dnfInstaller is an installer using yum to add and remove a component
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
