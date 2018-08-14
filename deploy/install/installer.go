package install

import (
	"bytes"
	"fmt"
	"text/template"
	"time"

	"github.com/CS-SI/SafeScale/deploy/install/api"
	"github.com/CS-SI/SafeScale/system"

	"github.com/CS-SI/SafeScale/utils/brokeruse"
)

const (
	componentScriptTemplateContent = `
rm -f /var/tmp/{{.Name}}.component.{{.Action}}.log
exec 1<&-
exec 2<&-
exec 1<>/var/tmp/{{.Name}}.component.{{.Action}}.log
exec 2>&1

{{ .CommonTools }}

{{ .Content }}
`
)

var (
	componentScriptTemplate *template.Template
)

// scriptInstaller is an installer using script to add and remove a component
type scriptInstaller struct{}

func (i *scriptInstaller) GetName() string {
	return "script"
}

// realizeScript envelops the script with log redirection to /var/tmp/component.<name>.<action>.log
// and ensures CommonTools are there
func (i *scriptInstaller) realizeScript(params map[string]interface{}) (string, error) {
	var err error

	if componentScriptTemplate == nil {
		// parse then execute the template
		componentScriptTemplate, err = template.New("component_script.sh").Parse(componentScriptTemplateContent)
		if err != nil {
			return "", fmt.Errorf("error parsing script template: %s", err.Error())
		}
	}

	// Configures CommonTools template var
	commonTools, err := system.RealizeCommonTools()
	if err != nil {
		return "", err
	}
	params["CommonTools"] = commonTools

	dataBuffer := bytes.NewBufferString("")
	err = componentScriptTemplate.Execute(dataBuffer, params)
	if err != nil {
		return "", fmt.Errorf("failed to realize %s script: %s", params["Action"], err.Error())
	}
	return dataBuffer.String(), nil

}

// Check checks if the component is installed, using the check script in Specs
func (i *scriptInstaller) Check(c api.ComponentAPI, t api.TargetAPI) (bool, error) {
	specs := c.GetSpecs()
	if specs.IsSet("component.installers.script.check") {
		checkScript := specs.GetString("component.installers.script.check")
		if len(checkScript) > 0 {
			cmdStr, err := i.realizeScript(map[string]interface{}{
				"Name":    c.GetName(),
				"Content": checkScript,
				"Action":  "check",
			})
			if err != nil {
				return false, err
			}
			filename := fmt.Sprintf("/var/tmp/%s_check.sh", c.GetName())
			err = uploadStringToTargetFile(cmdStr, t, filename)
			if err != nil {
				return false, err
			}
			retcode, _, _, err := brokeruse.SSHRun(t.GetName(),
				fmt.Sprintf("sudo bash %s ; #sudo rm -f %s", filename, filename),
				30*time.Minute)
			if err != nil {
				return false, err
			}
			if retcode != 0 {
				return false, fmt.Errorf("install script for component '%s' failed, retcode=%d", c.GetName(), retcode)
			}
			return true, nil
		}
		return false, fmt.Errorf("syntax error in component '%s' specification file: 'check' is empty", c.GetName())
	}
	return false, fmt.Errorf("syntax error in component '%s' specification file: no key 'check' found", c.GetName())
}

// Add installs the component using the install script in Specs
func (i *scriptInstaller) Add(c api.ComponentAPI, t api.TargetAPI) error {
	specs := c.GetSpecs()
	if specs.IsSet("component.installers.script.install") {
		addScript := specs.GetString("component.installers.script.install")
		if len(addScript) > 0 {
			cmdStr, err := i.realizeScript(map[string]interface{}{
				"Name":    c.GetName(),
				"Content": addScript,
				"Action":  "install",
			})
			if err != nil {
				return err
			}
			filename := fmt.Sprintf("/var/tmp/%s_install.sh", c.GetName())
			err = uploadStringToTargetFile(cmdStr, t, filename)
			if err != nil {
				return err
			}
			retcode, _, _, err := brokeruse.SSHRun(t.GetName(),
				fmt.Sprintf("sudo bash %s; #sudo rm -f %s", filename, filename),
				30*time.Minute)
			if err != nil {
				return err
			}
			if retcode != 0 {
				return fmt.Errorf("install script for component '%s' failed, retcode=%d", c.GetName(), retcode)
			}
			return nil
		}
		return fmt.Errorf("syntax error in component '%s' specification file: 'install' is empty", c.GetName())
	}
	return fmt.Errorf("syntax error in component '%s' specification file: no key 'install' found", c.GetName())
}

// Remove uninstalls the component using the RemoveScript script
func (i *scriptInstaller) Remove(c api.ComponentAPI, t api.TargetAPI) error {
	specs := c.GetSpecs()
	if specs.IsSet("component.installers.script.uninstall") {
		removeScript := specs.GetString("component.installers.script.uninstall")
		if len(removeScript) > 0 {
			cmdStr, err := i.realizeScript(map[string]interface{}{
				"Name":    c.GetName(),
				"Content": removeScript,
				"Action":  "uninstall",
			})
			if err != nil {
				return err
			}
			filename := fmt.Sprintf("/var/tmp/%s_uninstall.sh", c.GetName())
			err = uploadStringToTargetFile(cmdStr, t, filename)
			if err != nil {
				return err
			}
			retcode, _, _, err := brokeruse.SSHRun(t.GetName(),
				fmt.Sprintf("sudo bash %s; #sudo rm -f %s", filename, filename),
				30*time.Minute)
			if err != nil {
				return err
			}
			if retcode != 0 {
				return fmt.Errorf("uninstall script for component '%s' failed, retcode=%d", c.GetName(), retcode)
			}
			return nil
		}
		return fmt.Errorf("syntax error in component '%s' specification file: 'uninstall' is empty", c.GetName())
	}
	return fmt.Errorf("syntax error in component '%s' specification file: no key 'uninstall' found", c.GetName())
}

// NewScriptInstaller creates a new instance of Installer using script
func NewScriptInstaller() api.InstallerAPI {
	return &scriptInstaller{}
}

// aptInstaller is an installer using script to add and remove a component
type aptInstaller struct{}

func (i *aptInstaller) GetName() string {
	return "apt"
}

// Check checks if the component is installed
func (i *aptInstaller) Check(c api.ComponentAPI, t api.TargetAPI) (bool, error) {
	specs := c.GetSpecs()
	if specs.IsSet("component.installers.apt.package") {
		packageName := specs.GetString("component.installers.apt.package")
		if len(packageName) > 0 {
			cmdStr := fmt.Sprintf("sudo dpkg-query -s '%s' &>/dev/null", packageName)
			retcode, _, _, err := brokeruse.SSHRun(t.GetName(), cmdStr, 30*time.Minute)
			if err != nil {
				return false, err
			}
			if retcode != 0 {
				return false, fmt.Errorf("install command failed for component '%s'", c.GetName())
			}
			return true, nil
		}
		return false, fmt.Errorf("syntax error in component '%s' specification file: 'package' is empty", c.GetName())
	}
	return false, fmt.Errorf("syntax error in component '%s' specification file: no key 'package' found", c.GetName())
}

// Add installs the component using apt
func (i *aptInstaller) Add(c api.ComponentAPI, t api.TargetAPI) error {
	specs := c.GetSpecs()
	if specs.IsSet("component.installers.apt.package") {
		packageName := specs.GetString("component.installers.apt.package")
		if len(packageName) > 0 {
			cmdStr := fmt.Sprintf("sudo apt-get update -y; sudo apt-get install -y '%s'", packageName)
			retcode, _, _, err := brokeruse.SSHRun(t.GetName(), cmdStr, 30*time.Minute)
			if err != nil {
				return err
			}
			if retcode != 0 {
				return fmt.Errorf("install command failed for component '%s'", c.GetName())
			}
			return nil
		}
		return fmt.Errorf("syntax error in component '%s' specification file: 'package' is empty", c.GetName())
	}
	return fmt.Errorf("syntax error in component '%s' specification file: no key 'package' found", c.GetName())
}

// Remove uninstalls the component using the RemoveScript script
func (i *aptInstaller) Remove(c api.ComponentAPI, t api.TargetAPI) error {
	specs := c.GetSpecs()
	if specs.IsSet("component.installers.apt.package") {
		packageName := specs.GetString("component.installers.apt.package")
		if len(packageName) > 0 {
			cmdStr := fmt.Sprintf("sudo apt-get remove -y '%s'", packageName)
			retcode, _, _, err := brokeruse.SSHRun(t.GetName(), cmdStr, 30*time.Minute)
			if err != nil {
				return err
			}
			if retcode != 0 {
				return fmt.Errorf("uninstall command failed for component '%s'", c.GetName())
			}
			return nil
		}
		return fmt.Errorf("syntax error in component '%s' specification file: 'package' is empty", c.GetName())
	}
	return fmt.Errorf("syntax error in component '%s' specification file: no key 'package' found", c.GetName())
}

// NewAptInstaller creates a new instance of Installer using script
func NewAptInstaller() api.InstallerAPI {
	return &aptInstaller{}
}

// yumInstaller is an installer using yum to add and remove a component
type yumInstaller struct{}

func (i *yumInstaller) GetName() string {
	return "yum"
}

// Check checks if the the component is installed
func (i *yumInstaller) Check(c api.ComponentAPI, t api.TargetAPI) (bool, error) {
	specs := c.GetSpecs()
	if specs.IsSet("component.installers.yum.package") {
		packageName := specs.GetString("component.installers.yum.package")
		if len(packageName) > 0 {
			cmdStr := fmt.Sprintf("sudo rpm -q %s &>/dev/null", packageName)
			retcode, _, _, err := brokeruse.SSHRun(t.GetName(), cmdStr, 30*time.Minute)
			if err != nil {
				return false, err
			}
			if retcode != 0 {
				return false, fmt.Errorf("install command failed for component '%s'", c.GetName())
			}
			return true, nil
		}
		return false, fmt.Errorf("syntax error in component '%s' specification file: 'package' is empty", c.GetName())
	}
	return false, fmt.Errorf("syntax error in component '%s' specification file: no key 'package' found", c.GetName())
}

// Add installs the component using the AddScript script
func (i *yumInstaller) Add(c api.ComponentAPI, t api.TargetAPI) error {
	specs := c.GetSpecs()
	if specs.IsSet("component.installers.yum.package") {
		packageName := specs.GetString("component.installers.yum.package")
		if len(packageName) > 0 {
			cmdStr := fmt.Sprintf("sudo yum makecache fast; sudo yum install -y %s", packageName)
			retcode, _, _, err := brokeruse.SSHRun(t.GetName(), cmdStr, 30*time.Minute)
			if err != nil {
				return err
			}
			if retcode != 0 {
				return fmt.Errorf("install command failed for component '%s'", c.GetName())
			}
			return nil
		}
		return fmt.Errorf("syntax error in component '%s' specification file: 'package' is empty", c.GetName())
	}
	return fmt.Errorf("syntax error in component '%s' specification file: no key 'package' found", c.GetName())
}

// Remove uninstalls the component using the RemoveScript script
func (i *yumInstaller) Remove(c api.ComponentAPI, t api.TargetAPI) error {
	specs := c.GetSpecs()
	if specs.IsSet("component.installers.yum.package") {
		packageName := specs.GetString("component.installers.yum.package")
		if len(packageName) > 0 {
			cmdStr := fmt.Sprintf("sudo yum remove -y %s", packageName)
			retcode, _, _, err := brokeruse.SSHRun(t.GetName(), cmdStr, 30*time.Minute)
			if err != nil {
				return err
			}
			if retcode != 0 {
				return fmt.Errorf("uninstall command failed for component '%s'", c.GetName())
			}
			return nil
		}
		return fmt.Errorf("syntax error in component '%s' specification file: 'package' is empty", c.GetName())
	}
	return fmt.Errorf("syntax error in component '%s' specification file: no key 'package' found", c.GetName())
}

// NewYumInstaller creates a new instance of Installer using script
func NewYumInstaller() api.InstallerAPI {
	return &yumInstaller{}
}

// dnfInstaller is an installer using yum to add and remove a component
type dnfInstaller struct{}

func (i *dnfInstaller) GetName() string {
	return "dnf"
}

// Check checks if the component is installed
func (i *dnfInstaller) Check(c api.ComponentAPI, t api.TargetAPI) (bool, error) {
	specs := c.GetSpecs()
	if specs.IsSet("component.installers.dnf.package") {
		packageName := specs.GetString("component.installers.dnf.package")
		if len(packageName) > 0 {
			cmdStr := fmt.Sprintf("sudo dnf list installed %s &>/dev/null", packageName)
			retcode, _, _, err := brokeruse.SSHRun(t.GetName(), cmdStr, 30*time.Minute)
			if err != nil {
				return false, err
			}
			if retcode != 0 {
				return false, fmt.Errorf("install command failed for component '%s'", c.GetName())
			}
			return true, nil
		}
		return false, fmt.Errorf("syntax error in component '%s' specification file: 'package' is empty", c.GetName())
	}
	return false, fmt.Errorf("syntax error in component '%s' specification file: no key 'package' found", c.GetName())
}

// Add installs the component using the AddScript script
func (i *dnfInstaller) Add(c api.ComponentAPI, t api.TargetAPI) error {
	specs := c.GetSpecs()
	if specs.IsSet("component.installers.dnf.package") {
		packageName := specs.GetString("component.installers.dnf.package")
		if len(packageName) > 0 {
			cmdStr := fmt.Sprintf("sudo dnf install -y %s", packageName)
			retcode, _, _, err := brokeruse.SSHRun(t.GetName(), cmdStr, 30*time.Minute)
			if err != nil {
				return err
			}
			if retcode != 0 {
				return fmt.Errorf("install command failed for component '%s'", c.GetName())
			}
			return nil
		}
		return fmt.Errorf("syntax error in component '%s' specification file: 'package' is empty", c.GetName())
	}
	return fmt.Errorf("syntax error in component '%s' specification file: no key 'package' found", c.GetName())
}

// Remove uninstalls the component using the RemoveScript script
func (i *dnfInstaller) Remove(c api.ComponentAPI, t api.TargetAPI) error {
	specs := c.GetSpecs()
	if specs.IsSet("component.installers.dnf.package") {
		packageName := specs.GetString("component.installers.dnf.package")
		if len(packageName) > 0 {
			cmdStr := fmt.Sprintf("sudo dnf uninstall -y %s", packageName)
			retcode, _, _, err := brokeruse.SSHRun(t.GetName(), cmdStr, 30*time.Minute)
			if err != nil {
				return err
			}
			if retcode != 0 {
				return fmt.Errorf("uninstall command failed for component '%s'", c.GetName())
			}
			return nil
		}
		return fmt.Errorf("syntax error in component '%s' specification file: 'package' is empty", c.GetName())
	}
	return fmt.Errorf("syntax error in component '%s' specification file: no key 'package' found", c.GetName())
}

// NewDnfInstaller creates a new instance of Installer using script
func NewDnfInstaller() api.InstallerAPI {
	return &dnfInstaller{}
}
