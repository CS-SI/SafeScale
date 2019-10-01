/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
	"io/ioutil"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/spf13/viper"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/install/enums/Method"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
)

var (
	// EmptyValues corresponds to no values for the feature
	EmptyValues = map[string]interface{}{}
	// checkCache  = utils.NewMapCache()
)

// Variables defines the parameters a Installer may need
type Variables map[string]interface{}

// Clone clones the content of a Variables
func (v Variables) Clone() Variables {
	clone := Variables{}
	for k, v := range v {
		clone[k] = v
	}
	return clone
}

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
	// AddUnconditionally tells to not check before addition (no effect for check or removal)
	AddUnconditionally bool
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
	task  concurrency.Task
}

// ListFeatures lists all features suitable for hosts or clusters
func ListFeatures(suitableFor string) ([]interface{}, error) {
	features := allEmbeddedMap
	cfgFiles := []interface{}{}

	var paths []string
	paths = append(paths, utils.AbsPathify("$HOME/.safescale/features"))
	paths = append(paths, utils.AbsPathify("$HOME/.config/safescale/features"))
	paths = append(paths, utils.AbsPathify("/etc/safescale/features"))

	for _, path := range paths {
		files, err := ioutil.ReadDir(path)
		if err == nil {
			for _, f := range files {
				if isCfgFile := strings.HasSuffix(strings.ToLower(f.Name()), ".yml"); isCfgFile == true {
					feature, err := NewFeature(concurrency.RootTask(), strings.Replace(strings.ToLower(f.Name()), ".yml", "", 1))
					if err != nil {
						log.Error(err)
						continue
					}
					if _, ok := allEmbeddedMap[feature.displayName]; !ok {
						allEmbeddedMap[feature.displayName] = feature
					}
				}
			}
		}
	}

	for _, feature := range features {
		switch suitableFor {
		case "host":
			yamlKey := "feature.suitableFor.host"
			if feature.Specs().IsSet(yamlKey) {
				value := strings.ToLower(feature.Specs().GetString(yamlKey))
				if value == "ok" || value == "yes" || value == "true" || value == "1" {
					cfgFiles = append(cfgFiles, feature.fileName)
				}
			}
		case "cluster":
			yamlKey := "feature.suitableFor.cluster"
			if feature.Specs().IsSet(yamlKey) {
				values := strings.Split(strings.ToLower(feature.Specs().GetString(yamlKey)), ",")
				if values[0] == "all" || values[0] == "dcos" || values[0] == "k8s" || values[0] == "boh" || values[0] == "swarm" || values[0] == "ohpc" {
					cfg := struct {
						FeatureName    string   `json:"feature"`
						ClusterFlavors []string `json:"available-cluster-flavors"`
					}{feature.displayName, []string{}}
					for _, flavor := range values {
						cfg.ClusterFlavors = append(cfg.ClusterFlavors, flavor)
					}
					cfgFiles = append(cfgFiles, cfg)
				}
			}
		default:
			return nil, fmt.Errorf("unknown parameter value : %s \n (should be host or cluster)", suitableFor)
		}

	}

	return cfgFiles, nil
}

// NewFeature searches for a spec file name 'name' and initializes a new Feature object
// with its content
func NewFeature(task concurrency.Task, name string) (*Feature, error) {
	if name == "" {
		panic("name is empty!")
	}

	v := viper.New()
	v.AddConfigPath(".")
	v.AddConfigPath("$HOME/.safescale/features")
	v.AddConfigPath("$HOME/.config/safescale/features")
	v.AddConfigPath("/etc/safescale/features")
	v.SetConfigName(name)

	var feat Feature
	err := v.ReadInConfig()
	if err != nil {
		switch err.(type) {
		case viper.ConfigFileNotFoundError:
			// Failed to find a spec file on filesystem, trying with embedded ones
			err = nil
			var ok bool
			if _, ok = allEmbeddedMap[name]; !ok {
				err = fmt.Errorf("failed to find a feature named '%s'", name)
			} else {
				feat = *allEmbeddedMap[name]
				feat.task = task
			}
		default:
			err = fmt.Errorf("failed to read the specification file of feature called '%s': %s", name, err.Error())
		}
	} else {
		if v.IsSet("feature") {
			feat = Feature{
				fileName:    name + ".yml",
				displayName: name,
				specs:       v,
				task:        task,
			}
		}
	}
	return &feat, err
}

// NewEmbeddedFeature searches for an embedded featured named 'name' and initializes a new Feature object
// with its content
func NewEmbeddedFeature(task concurrency.Task, name string) (*Feature, error) {
	if name == "" {
		panic("name is empty!")
	}

	var (
		feat Feature
		err  error
	)
	if _, ok := allEmbeddedMap[name]; !ok {
		err = fmt.Errorf("failed to find a feature named '%s'", name)
	} else {
		feat = *allEmbeddedMap[name]
		feat.task = task
	}
	return &feat, err
}

// installerOfMethod instanciates the right installer corresponding to the method
func (f *Feature) installerOfMethod(method Method.Enum) Installer {
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
func (f *Feature) DisplayName() string {
	return f.displayName
}

// Filename returns the name of the feature
func (f *Feature) Filename() string {
	return f.displayName
}

// DisplayFilename returns the full file name, with [embedded] added at the end if the
// feature is embedded.
func (f *Feature) DisplayFilename() string {
	filename := f.fileName
	if f.embedded {
		filename += " [embedded]"
	}
	return filename
}

// Specs returns a copy of the spec file (we don't want external use to modify Feature.specs)
func (f *Feature) Specs() *viper.Viper {
	roSpecs := *f.specs
	return &roSpecs
}

// Applyable tells if the feature is installable on the target
func (f *Feature) Applyable(t Target) bool {
	methods := t.Methods()
	for _, k := range methods {
		installer := f.installerOfMethod(k)
		if installer != nil {
			return true
		}
	}
	return false
}

// Check if feature is installed on target
// Check is ok if error is nil and Results.Successful() is true
func (f *Feature) Check(t Target, v Variables, s Settings) (Results, error) {
	// cacheKey := f.DisplayName() + "@" + t.Name()
	// if anon, ok := checkCache.Get(cacheKey); ok {
	// 	return anon.(Results), nil
	// }

	methods := t.Methods()
	var installer Installer
	for _, method := range methods {
		if f.specs.IsSet(fmt.Sprintf("feature.install.%s", strings.ToLower(method.String()))) {
			installer = f.installerOfMethod(method)
			if installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return nil, fmt.Errorf("failed to find a way to check '%s'", f.DisplayName())
	}

	log.Debugf("Checking if feature '%s' is installed on %s '%s'...\n", f.DisplayName(), t.Type(), t.Name())

	// 'v' may be updated by parallel tasks, so use copy of it
	myV := make(Variables)
	for key, value := range v {
		myV[key] = value
	}

	// Inits implicit parameters
	f.setImplicitParameters(t, myV)

	// Checks required parameters have value
	err := checkParameters(f, myV)
	if err != nil {
		return nil, err
	}

	results, err := installer.Check(f, t, myV, s)
	// _ = checkCache.ForceSet(cacheKey, results)
	return results, err
}

// Add installs the feature on the target
// Installs succeeds if error == nil and Results.Successful() is true
func (f *Feature) Add(t Target, v Variables, s Settings) (Results, error) {
	if f == nil {
		return nil, utils.InvalidInstanceError()
	}

	methods := t.Methods()
	var (
		installer Installer
		i         uint8
	)
	for i = 1; i <= uint8(len(methods)); i++ {
		method := methods[i]
		if f.specs.IsSet(fmt.Sprintf("feature.install.%s", strings.ToLower(method.String()))) {
			installer = f.installerOfMethod(method)
			if installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return nil, fmt.Errorf("failed to find a way to install '%s'", f.DisplayName())
	}

	defer utils.Stopwatch{}.OnExitLogInfo(
		fmt.Sprintf("Starting addition of feature '%s' on %s '%s'...", f.DisplayName(), t.Type(), t.Name()),
		fmt.Sprintf("Ending addition of feature '%s' on %s '%s'", f.DisplayName(), t.Type(), t.Name()),
	)

	// 'v' may be updated by parallel tasks, so use copy of it
	myV := make(Variables)
	for key, value := range v {
		myV[key] = value
	}

	// Inits implicit parameters
	f.setImplicitParameters(t, myV)

	// Checks required parameters have value
	err := checkParameters(f, myV)
	if err != nil {
		return nil, err
	}

	if !s.AddUnconditionally {
		results, err := f.Check(t, v, s)
		if err != nil {
			return nil, fmt.Errorf("failed to check feature '%s': %s", f.DisplayName(), err.Error())
		}
		if results.Successful() {
			log.Infof("Feature '%s' is already installed.", f.DisplayName())
			return results, nil
		}
	}

	if !s.SkipFeatureRequirements {
		err := f.installRequirements(t, v, s)
		if err != nil {
			return nil, fmt.Errorf("failed to install requirements: %s", err.Error())
		}
	}
	results, err := installer.Add(f, t, myV, s)
	if err == nil {
		// _ = checkCache.ForceSet(f.DisplayName()+"@"+t.Name(), results)
	}
	return results, err
}

// Remove uninstalls the feature from the target
func (f *Feature) Remove(t Target, v Variables, s Settings) (results Results, err error) {
	if f == nil {
		return nil, utils.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(nil, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()
	defer utils.OnExitLogError(tracer.TraceMessage(""), &err)

	results = Results{}
	methods := t.Methods()
	var installer Installer
	for _, method := range methods {
		if f.specs.IsSet(fmt.Sprintf("feature.install.%s", strings.ToLower(method.String()))) {
			installer = f.installerOfMethod(method)
			if installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return nil, fmt.Errorf("failed to find a way to uninstall '%s'", f.DisplayName())
	}

	defer utils.Stopwatch{}.OnExitLogInfo(
		fmt.Sprintf("Starting removal of feature '%s' from %s '%s'", f.DisplayName(), t.Type(), t.Name()),
		fmt.Sprintf("Ending removal of feature '%s' from %s '%s'", f.DisplayName(), t.Type(), t.Name()),
	)

	// 'v' may be updated by parallel tasks, so use copy of it
	myV := make(Variables)
	for key, value := range v {
		myV[key] = value
	}

	// Inits implicit parameters
	f.setImplicitParameters(t, myV)

	// Checks required parameters have value
	err = checkParameters(f, myV)
	if err != nil {
		return nil, err
	}

	results, err = installer.Remove(f, t, myV, s)
	// checkCache.Reset(f.DisplayName() + "@" + t.Name())
	return results, err
}

// installRequirements walks through requirements and installs them if needed
func (f *Feature) installRequirements(t Target, v Variables, s Settings) error {
	yamlKey := "feature.requirements.features"
	if f.specs.IsSet(yamlKey) {
		{
			hostInstance, clusterInstance, nodeInstance := determineContext(t)
			msgHead := fmt.Sprintf("Checking requirements of feature '%s'", f.DisplayName())
			var msgTail string
			if hostInstance != nil {
				msgTail = fmt.Sprintf("on host '%s'", hostInstance.host.Name)
			}
			if nodeInstance != nil {
				msgTail = fmt.Sprintf("on cluster node '%s'", nodeInstance.host.Name)
			}
			if clusterInstance != nil {
				msgTail = fmt.Sprintf("on cluster '%s'", clusterInstance.cluster.GetIdentity(f.task).Name)
			}
			log.Debugf("%s %s...\n", msgHead, msgTail)
		}
		for _, requirement := range f.specs.GetStringSlice(yamlKey) {
			needed, err := NewFeature(f.task, requirement)
			if err != nil {
				return fmt.Errorf("failed to find required feature '%s': %s", requirement, err.Error())
			}
			results, err := needed.Check(t, v, s)
			if err != nil {
				return fmt.Errorf("failed to check required feature '%s' for feature '%s': %s", requirement, f.DisplayName(), err.Error())
			}
			if !results.Successful() {
				results, err := needed.Add(t, v, s)
				if err != nil {
					return fmt.Errorf("failed to install required feature '%s': %s", requirement, err.Error())
				}
				if !results.Successful() {
					return fmt.Errorf("failed to install required feature '%s':\n%s", requirement, results.AllErrorMessages())
				}
			}
		}
	}
	return nil
}

// setImplicitParameters configures parameters that are implicitly defined, based on target
func (f *Feature) setImplicitParameters(t Target, v Variables) {
	hT, cT, nT := determineContext(t)
	if cT != nil {
		cluster := cT.cluster
		identity := cluster.GetIdentity(f.task)
		v["ClusterName"] = identity.Name
		v["ClusterComplexity"] = strings.ToLower(identity.Complexity.String())
		v["ClusterFlavor"] = strings.ToLower(identity.Flavor.String())
		networkCfg := cluster.GetNetworkConfig(f.task)
		// if networkCfg.VIP != nil {
		// 	v["GatewayIP"] = networkCfg.VIP.PrivateIP // VPL: Should be replaced by the next entry
		// 	v["DefaultRouteIP"] = networkCfg.VIP.PrivateIP
		// 	v["PublicIP"] = networkCfg.VIP.PublicIP // VPL: Should be replaced by the next entry
		// 	v["EndpointIP"] = networkCfg.VIP.PublicIP
		v["PrimaryGatewayIP"] = networkCfg.GatewayIP
		v["SecondaryGatewayIP"] = networkCfg.SecondaryGatewayIP
		v["DefaultRouteIP"] = networkCfg.DefaultRouteIP
		v["GatewayIP"] = v["DefaultRouteIP"] // legacy ...
		v["PrimaryPublicIP"] = networkCfg.PrimaryPublicIP
		v["SecondaryPublicIP"] = networkCfg.SecondaryPublicIP
		v["EndpointIP"] = networkCfg.EndpointIP
		v["PublicIP"] = v["EndpointIP"] // legacy ...
		v["Masters"] = cluster.ListMasters(f.task)
		v["MasterNames"] = cluster.ListMasterNames(f.task)
		v["MasterIDs"] = cluster.ListMasterIDs(f.task)
		v["MasterIPs"] = cluster.ListMasterIPs(f.task)
		if _, ok := v["Username"]; !ok {
			v["Username"] = "cladm"
			v["Password"] = identity.AdminPassword
		}
		if _, ok := v["CIDR"]; !ok {
			v["CIDR"] = networkCfg.CIDR
		}
	} else {
		var host *pb.Host
		if nT != nil {
			host = nT.HostTarget.host
		}
		if hT != nil {
			host = hT.host
		}

		if host == nil {
			panic("nil host in feature")
		}

		// v["Hostname"] = host.Name
		// v["HostIP"] = host.PrivateIp
		gw := gatewayFromHost(host)
		if gw != nil {
			v["GatewayIP"] = gw.PrivateIp
			v["PublicIP"] = gw.PublicIp
		} else {
			v["PublicIP"] = host.PublicIp
		}
		if _, ok := v["Username"]; !ok {
			v["Username"] = "safescale"
		}
	}
}
