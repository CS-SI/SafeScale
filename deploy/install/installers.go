package services

import (
	"fmt"

	"github.com/CS-SI/SafeScale/cluster/api/Flavor"

	clusterapi "github.com/CS-SI/SafeScale/cluster/api"
)

type dcosPackageInstaller struct {
	Installer
}

func (i *dcosPackageInstaller) Install(c clusterapi.ClusterAPI) error {
	config := c.GetConfig()
	if config.Flavor != Flavor.DCOS {
		return fmt.Errorf("cluster '%s' can't install using DCOS Packager", c.Name)
	}
	return fmt.Errorf("dcosPackageInstaller.Install() not yet implemented")
}

func (i *dcosPackageInstaller) Delete(c clusterapi.ClusterAPI) error {
	if c == nil {
		panic("c is nil!")
	}

	config := c.GetConfig()
	if config.Flavor != Flavor.DCOS {
		return fmt.Errorf("cluster '%s' can't install using DCOS Packager", c.Name)
	}
	return fmt.Errorf("dcosPackageInstaller.Delete() not yet implemented")
}

// NewDCOSPackageInstaller creates a new Installer using DCOS packager
func NewDCOSPackageInstaller(pkgname string) InstallerAPI {
	return &dcosPackageInstaller{
		Name:    pkgname,
		Cluster: c,
	}
	return &i
}

type helmInstaller struct {
	Installer
}

func (i *helmInstaller) Install(c clusterapi.ClusterAPI) error {
	config := c.GetConfig()
	if _, ok := config.Services["kubernetes"]; !ok {
		return fmt.Errorf("can't use Helm without service Kubernetes running")
	}
	return fmt.Errorf("helmInstaller.Install() not yet implemented")
}

func (i *helmInstaller) Delete(c clusterapi.ClusterAPI) error {
	config := c.GetConfig()
	if _, ok := config.Services["kubernetes"]; !ok {
		return fmt.Errorf("can't use Helm without service Kubernetes running")
	}
	return fmt.Errorf("helmInstaller.Delete() not yet implemented")
}

// NewHelmInstaller creates a new instance of Installer using Helm
func NewHelmInstaller(pkgname string) InstallerAPI {
	return &helmInstaller{
		Name: name,
	}
}

type scriptInstaller struct {
	Installer
}

func (i *scriptInstaller) Install(c clusterapi.ClusterAPI) error {
	return fmt.Errorf("helmInstaller.Install() not yet implemented")
}

func (i *scriptInstaller) Delete(c clusterapi.ClusterAPI) error {
	return fmt.Errorf("helmInstaller.Delete() not yet implemented")
}

// NewScriptInstaller creates a new instance of Installer using script
func NewScriptInstaller(pkgname string) InstallerAPI {
	return &helmInstaller{
		Name: name,
	}
}
