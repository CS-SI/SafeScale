package install

import (
	"fmt"

	installapi "github.com/CS-SI/SafeScale/deploy/install/api"

	clusterapi "github.com/CS-SI/SafeScale/deploy/cluster/api"
	"github.com/CS-SI/SafeScale/deploy/cluster/api/Flavor"
)

type dcosPackageInstaller struct {
	installer installapi.Installer
}

// Add ...
func (i *dcosPackageInstaller) Add(t installapi.TargetAPI) error {
	c, ok := t.(clusterapi.ClusterAPI)
	if !ok {
		panic("cluster.install.dcosPackageInstaller.Add() applied on non-cluster target!")
	}
	config := c.GetConfig()
	if config.Flavor != Flavor.DCOS {
		return fmt.Errorf("cluster '%s' can't install using DCOS Packager", c.Name)
	}
	return fmt.Errorf("dcosPackageInstaller.Add() not yet implemented")
}

// Remove ...
func (i *dcosPackageInstaller) Remove(t installapi.TargetAPI) error {
	c, ok := t.(clusterapi.ClusterAPI)
	if !ok {
		panic("cluster.install.dcosPackageInstaller.Remove() applied on non-cluster target!")
	}
	config := c.GetConfig()
	if config.Flavor != Flavor.DCOS {
		return fmt.Errorf("cluster '%s' can't uninstall using DCOS Packager", c.Name)
	}
	return fmt.Errorf("dcosPackageInstaller.Remove() not yet implemented")
}

// NewDCOSPackageInstaller creates a new Installer using DCOS packager
func NewDCOSPackageInstaller(pkgname string) installapi.InstallerAPI {
	return &dcosPackageInstaller{
		installer: Installer{
			Name: pkgname,
		},
	}
	return &i
}

type helmInstaller struct {
	installer installapi.Installer
}

func (i *helmInstaller) Add(t installapi.TargetAPI) error {
	c, ok := t.(clusterapi.ClusterAPI)
	if !ok {
		panic("cluster.install.helmInstaller.Add() applied on non-cluster target!")
	}
	return fmt.Errorf("helmInstaller.Add() not yet implemented")
}

func (i *helmInstaller) Remove(t installapi.TargetAPI) error {
	c, ok := t.(clusterapi.ClusterAPI)
	if !ok {
		panic("cluster.install.helmInstaller.Remove() applied on non-cluster target!")
	}
	//config := c.GetConfig()
	return fmt.Errorf("helmInstaller.Remove() not yet implemented")
}

// NewHelmInstaller creates a new instance of Installer using Helm
func NewHelmInstaller(pkgname string) installapi.InstallerAPI {
	return &helmInstaller{
		Name: pkgname,
		// Dependencies: []string{
		// 	"kubernetes",
		// },
	}
}

type scriptInstaller struct {
	installapi.Installer
}

// Add ...
func (i *scriptInstaller) Add(t installapi.TargetAPI) error {
	c, ok := t.(clusterapi.ClusterAPI)
	if !ok {
		panic("cluster.install.scriptInstaller.Add() applied on non-cluster target!")
	}

	return fmt.Errorf("cluster.install.helmInstaller.Add() not yet implemented")
}

// Remove ...
func (i *scriptInstaller) Remove(t installapi.TargetAPI) error {
	c, ok := t.(clusterapi.ClusterAPI)
	if !ok {
		panic("cluster.install.scriptInstaller.Remove() applied on non-cluster target!")
	}

	return fmt.Errorf("cluster.install.scriptInstaller.Remove() not yet implemented")
}

// NewScriptInstaller creates a new instance of an installer using script
func NewScriptInstaller(pkgname string) installapi.InstallerAPI {
	return &scriptInstaller{
		Name: pkgname,
	}
}

type dcosInstaller struct {
	installer Installer
}

type dcosInstallerParameters struct {
}

func (i *dcosInstaller) GetName() {
	return i.installer.GetName()
}

// Add installs the component using DCOS
func (i *dcosInstaller) Add(t api.TargetAPI) error {
	if i.AddCommand != "" {
		cmdStr := "sudo -u cladm -i " + i.AddCommand
		return brokerclient.New().Ssh.Run(h.ID, cmdStr, brokerclient.DefaultTimeout)
	}
	return fmt.Errorf("no command to add component found")
}

// Remove uninstalls the component using the RemoveScript script
func (i *dcosInstaller) Remove(t api.TargetAPI) error {
	if i.RemoveCommand != "" {
		cmdStr := "sudo -u cladm -i " + i.AddCommand
		return brokerclient.New().Ssh.Run(h.ID, cmdStr, brokerclient.DefaultTimeout)
	}
	return fmt.Errorf("no command to remove component found")
}

// NewDCOSPackageInstaller creates a new instance of Installer using script
func NewDCOSPackageInstaller(pkgname string, params dcosInstallerParameters) api.InstallerAPI {
	return &scriptInstaller{
		Name:   name,
		params: params,
	}
}
