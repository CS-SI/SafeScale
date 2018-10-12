/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package install

import (
	"fmt"
	"log"
	"strings"

	"github.com/CS-SI/SafeScale/deploy/install/enums/Method"

	"github.com/spf13/viper"
)

var (
	// EmptyValues corresponds to no values for the feature
	EmptyValues = map[string]interface{}{}
)

// Variables defines the parameters a Installer may need
type Variables map[string]interface{}

// Settings are used to tune the feature
type Settings struct {
	// SkipProxy to tell not to try to set reverse proxy
	SkipProxy bool
	// Serialize force not to parallel hosts in step
	Serialize bool
	// SkipFeatureRequirements tells not to install required features
	SkipFeatureRequirements bool
	// SkipSizingRequirements tells not to check sizing requirements
	SkipSizingRequirements bool
}

// Feature contains the information about an installable feature
type Feature struct {
	// displayName is the name of the service
	displayName string
	// fileName is the name of the specification file
	fileName string
	// embedded tells if the feature is embedded in deploy
	embedded bool
	// Installers defines the installers available for the feature
	installers map[Method.Enum]Installer
	// Dependencies lists other feature(s) (by name) needed by this one
	//dependencies []string
	// Management contains a string map of data that could be used to manage the feature (if it makes sense)
	// This could be used to explain to Service object how to manage the feature, to react as a service
	//Management map[string]interface{}
	// specs is the Viper instance containing feature specification
	specs *viper.Viper
}

// NewFeature searches for a spec file name 'name' and initializes a new Feature object
// with its content
func NewFeature(name string) (*Feature, error) {
	if name == "" {
		panic("name is empty!")
	}

	v := viper.New()
	v.AddConfigPath(".")
	v.AddConfigPath("$HOME/.safescale/features")
	v.AddConfigPath("$HOME/.config/safescale/features")
	v.AddConfigPath("/etc/safescale/features")
	v.SetConfigName(name)

	var feature *Feature
	err := v.ReadInConfig()
	if err != nil {
		switch err.(type) {
		case viper.ConfigFileNotFoundError:
			// Failed to find a spec file on filesystem, trying with embedded ones
			err = nil
			var ok bool
			if feature, ok = allEmbeddedMap[name]; !ok {
				err = fmt.Errorf("failed to find a feature named '%s'", name)
			}
		default:
			err = fmt.Errorf("failed to read the specification file of feature called '%s': %s", name, err.Error())
		}
	} else {
		if !v.IsSet("feature.name") {
			return nil, fmt.Errorf("syntax error in specification file: missing key 'name'")
		}
		if v.IsSet("feature") {
			feature = &Feature{
				fileName:    name + ".yml",
				displayName: v.GetString("feature.name"),
				specs:       v,
			}
		}
	}
	return feature, err
}

// installerOfMethod instanciates the right installer corresponding to the method
func (c *Feature) installerOfMethod(method Method.Enum) Installer {
	var installer Installer
	switch method {
	case Method.Bash:
		installer = NewBashInstaller()
	case Method.Apt:
		installer = NewAptInstaller()
	case Method.Yum:
		installer = NewYumInstaller()
	case Method.Dnf:
		installer = NewDnfInstaller()
	case Method.DCOS:
		installer = NewDcosInstaller()
		//	case Method.Ansible:
		//		installer = NewAnsibleInstaller()
		//	case Method.Helm:
		//		installer = NewHelmInstaller()
	}
	return installer
}

// DisplayName returns the name of the feature
func (c *Feature) DisplayName() string {
	return c.displayName
}

// BaseFilename returns the name of the feature specification file without '.yml'
func (c *Feature) BaseFilename() string {
	return c.fileName
}

// DisplayFilename returns the full file name, with [embedded] added at the end if the
// feature is embedded.
func (c *Feature) DisplayFilename() string {
	filename := c.fileName + ".yml"
	if c.embedded {
		filename += " [embedded]"
	}
	return filename
}

// Specs returns the data from the spec file
func (c *Feature) Specs() *viper.Viper {
	return c.specs
}

// Applyable tells if the feature is installable on the target
func (c *Feature) Applyable(t Target) bool {
	methods := t.Methods()
	for _, k := range methods {
		installer := c.installerOfMethod(k)
		if installer != nil {
			return true
		}
	}
	return false
}

// Check if feature is installed on target
// Check is ok if error is nil and Results.Successful() is true
func (c *Feature) Check(t Target, v Variables, s Settings) (Results, error) {
	methods := t.Methods()
	var installer Installer
	for _, method := range methods {
		if c.specs.IsSet(fmt.Sprintf("feature.install.%s", strings.ToLower(method.String()))) {
			installer = c.installerOfMethod(method)
			if installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return nil, fmt.Errorf("failed to find a way to check '%s'", c.DisplayName())
	}

	//if debug
	if false {
		log.Printf("Checking if feature '%s' is installed on %s '%s'...\n", c.DisplayName(), t.Type(), t.Name())
	}

	// 'v' may be updated by parallel tasks, so use copy of it
	myV := make(Variables)
	for key, value := range v {
		myV[key] = value
	}

	// Inits implicit parameters
	setImplicitParameters(t, myV)

	// Checks required parameters have value
	err := checkParameters(c, myV)
	if err != nil {
		return nil, err
	}

	return installer.Check(c, t, myV, s)
}

// Add installs the feature on the target
// Installs succeeds if error == nil and Results.Successful() is true
func (c *Feature) Add(t Target, v Variables, s Settings) (Results, error) {
	methods := t.Methods()
	var (
		installer Installer
		i         uint8
	)
	for i = 1; i <= uint8(len(methods)); i++ {
		method := methods[i]
		if c.specs.IsSet(fmt.Sprintf("feature.install.%s", strings.ToLower(method.String()))) {
			installer = c.installerOfMethod(method)
			if installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return nil, fmt.Errorf("failed to find a way to install '%s'", c.DisplayName())
	}

	//if debug
	if false {
		log.Printf("Adding feature '%s' on %s '%s'...\n", c.DisplayName(), t.Type(), t.Name())
	}

	// 'v' may be updated by parallel tasks, so use copy of it
	myV := make(Variables)
	for key, value := range v {
		myV[key] = value
	}

	// Inits implicit parameters
	setImplicitParameters(t, myV)

	// Checks required parameters have value
	err := checkParameters(c, myV)
	if err != nil {
		return nil, err
	}

	return installer.Add(c, t, myV, s)
}

// Remove uninstalls the feature from the target
func (c *Feature) Remove(t Target, v Variables, s Settings) (Results, error) {
	methods := t.Methods()
	var installer Installer
	for _, method := range methods {
		if c.specs.IsSet(fmt.Sprintf("feature.install.%s", strings.ToLower(method.String()))) {
			installer = c.installerOfMethod(method)
			if installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return nil, fmt.Errorf("failed to find a way to uninstall '%s'", c.DisplayName())
	}
	//if debug
	if false {
		log.Printf("Removing feature '%s' from %s '%s'...\n", c.DisplayName(), t.Type(), t.Name())
	}

	// 'v' may be updated by parallel tasks, so use copy of it
	myV := make(Variables)
	for key, value := range v {
		myV[key] = value
	}

	// Inits implicit parameters
	setImplicitParameters(t, myV)

	// Checks required parameters have value
	err := checkParameters(c, myV)
	if err != nil {
		return nil, err
	}

	return installer.Remove(c, t, myV, s)
}
