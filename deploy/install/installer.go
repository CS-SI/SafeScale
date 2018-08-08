package install

import (
	"fmt"

	"github.com/CS-SI/SafeScale/deploy/install/api"

	"github.com/CS-SI/SafeScale/utils/brokeruse"
)

// Installer contains the information about an Installer
type Installer struct {
	// Name of the Installer
	Name string

	params api.InstallerParameters
}

// GetName ...
func (s *Installer) GetName() string {
	return s.Name
}

// scriptInstaller is an installer using script to add and remove a component
type scriptInstaller struct {
	installer Installer

	// AddScript contains the script to add the component
	AddScript string
	// RemoveScript contains the script to remove the component
	RemoveScript string
}

func (i *scriptInstaller) GetName() string {
	return i.installer.GetName()
}

// Add installs the component using the AddScript script
func (i *scriptInstaller) Add(t api.TargetAPI) error {
	if i.AddScript != "" {
		return brokeruse.SSHRun(t.GetName(), i.AddScript)
	}
	return fmt.Errorf("no script to add component found")
}

// Remove uninstalls the component using the RemoveScript script
func (i *scriptInstaller) Remove(t api.TargetAPI) error {
	if i.RemoveScript != "" {
		return brokeruse.SSHRun(t.GetName(), i.RemoveScript)
	}
	return fmt.Errorf("no script to remove component found")
}

// NewScriptInstaller creates a new instance of Installer using script
func NewScriptInstaller(pkgname string, params api.InstallerParameters) api.InstallerAPI {
	return &scriptInstaller{
		installer: Installer{
			Name:   pkgname,
			params: params,
		},
	}
}
