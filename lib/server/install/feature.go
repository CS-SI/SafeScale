/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

	"github.com/sirupsen/logrus"

	"github.com/spf13/viper"

	pb "github.com/CS-SI/SafeScale/lib"
	clusterpropsv1 "github.com/CS-SI/SafeScale/lib/server/cluster/control/properties/v1"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/property"
	"github.com/CS-SI/SafeScale/lib/server/install/enums/method"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

var (
	// EmptyValues corresponds to no values for the feature
	EmptyValues = map[string]interface{}{}
	// checkCache  = utils.NewMapCache()
)

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
	installers map[method.Enum]Installer
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
	var cfgFiles []interface{}

	var paths []string
	paths = append(paths, utils.AbsPathify("$HOME/.safescale/features"))
	paths = append(paths, utils.AbsPathify("$HOME/.config/safescale/features"))
	paths = append(paths, utils.AbsPathify("/etc/safescale/features"))

	var errors []error

	task, err := concurrency.NewTask()
	if err != nil {
		return nil, err
	}

	for _, path := range paths {
		files, err := ioutil.ReadDir(path)
		if err == nil {
			for _, f := range files {
				if strings.HasSuffix(strings.ToLower(f.Name()), ".yml") {
					feature, err := NewFeature(task, strings.Replace(strings.ToLower(f.Name()), ".yml", "", 1))
					if err != nil {
						logrus.Error(err)
						errors = append(errors, err)
						continue
					}
					if _, ok := allEmbeddedMap[feature.displayName]; !ok {
						allEmbeddedMap[feature.displayName] = feature
					}
				}
			}
		}
	}

	if len(errors) > 0 {
		return nil, scerr.ErrListError(errors)
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

					cfg.ClusterFlavors = append(cfg.ClusterFlavors, values...)

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
// error contains :
//    - *scerr.ErrNotFound if no feature is found by its name
//    - *scerr.ErrSyntax if feature found contains syntax error
func NewFeature(task concurrency.Task, name string) (_ *Feature, err error) {
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	v := viper.New()
	v.AddConfigPath(".")
	v.AddConfigPath("$HOME/.safescale/features")
	v.AddConfigPath("$HOME/.config/safescale/features")
	v.AddConfigPath("/etc/safescale/features")
	v.SetConfigName(name)

	var feat Feature
	err = v.ReadInConfig()
	if err != nil {
		switch err.(type) {
		case viper.ConfigFileNotFoundError:
			// Failed to find a spec file on filesystem, trying with embedded ones
			err = nil
			var ok bool
			if _, ok = allEmbeddedMap[name]; !ok {
				err = scerr.NotFoundError(fmt.Sprintf("failed to find a feature named '%s'", name))
			} else {
				feat = *allEmbeddedMap[name]
				feat.task = task
			}
		default:
			err = scerr.SyntaxError(fmt.Sprintf("failed to read the specification file of feature called '%s': %s", name, err.Error()))
		}
	} else if v.IsSet("feature") {
		feat = Feature{
			fileName:    name + ".yml",
			displayName: name,
			specs:       v,
			task:        task,
		}
	}

	return &feat, err
}

// NewEmbeddedFeature searches for an embedded featured named 'name' and initializes a new Feature object
// with its content
func NewEmbeddedFeature(task concurrency.Task, name string) (_ *Feature, err error) {
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	var feat Feature
	if _, ok := allEmbeddedMap[name]; !ok {
		err = scerr.NotFoundError(fmt.Sprintf("failed to find a feature named '%s'", name))
	} else {
		feat = *allEmbeddedMap[name]
		feat.task = task
	}
	return &feat, err
}

// installerOfMethod instanciates the right installer corresponding to the method
func (f *Feature) installerOfMethod(m method.Enum) Installer {
	var installer Installer
	switch m {
	case method.Bash:
		installer = NewBashInstaller()
	case method.Apt:
		installer = NewAptInstaller()
	case method.Yum:
		installer = NewYumInstaller()
		//	case method.Dnf:
		//		installer = NewDnfInstaller()
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
func (f *Feature) Check(t Target, v data.Map, s Settings) (_ Results, err error) {
	if f == nil {
		return nil, scerr.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(f.task, fmt.Sprintf("(): '%s' on %s '%s'", f.DisplayName(), t.Type(), t.Name()), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	// cacheKey := f.DisplayName() + "@" + t.Name()
	// if anon, ok := checkCache.Get(cacheKey); ok {
	// 	return anon.(Results), nil
	// }

	methods := t.Methods()
	var installer Installer
	for _, meth := range methods {
		if f.specs.IsSet(fmt.Sprintf("feature.install.%s", strings.ToLower(meth.String()))) {
			installer = f.installerOfMethod(meth)
			if installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return nil, fmt.Errorf("failed to find a way to check '%s'", f.DisplayName())
	}

	logrus.Debugf("Checking if feature '%s' is installed on %s '%s'...", f.DisplayName(), t.Type(), t.Name())

	// 'v' may be updated by parallel tasks, so use copy of it
	myV := make(data.Map)
	for key, value := range v {
		myV[key] = value
	}

	// Inits implicit parameters
	err = f.setImplicitParameters(t, myV)
	if err != nil {
		return nil, err
	}

	// Checks required parameters have value
	err = checkParameters(f, myV)
	if err != nil {
		return nil, err
	}

	results, err := installer.Check(f, t, myV, s)
	// _ = checkCache.ForceSet(cacheKey, results)
	return results, err
}

// Add installs the feature on the target
// Installs succeeds if error == nil and Results.Successful() is true
func (f *Feature) Add(t Target, v data.Map, s Settings) (_ Results, err error) {
	if f == nil {
		return nil, scerr.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(f.task, fmt.Sprintf("(): '%s' on %s '%s'", f.DisplayName(), t.Type(), t.Name()), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	methods := t.Methods()
	var (
		installer Installer
		i         uint8
	)
	for i = 1; i <= uint8(len(methods)); i++ {
		meth := methods[i]
		if f.specs.IsSet(fmt.Sprintf("feature.install.%s", strings.ToLower(meth.String()))) {
			installer = f.installerOfMethod(meth)
			if installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return nil, fmt.Errorf("failed to find a way to install '%s'", f.DisplayName())
	}

	defer temporal.NewStopwatch().OnExitLogInfo(
		fmt.Sprintf("Starting addition of feature '%s' on %s '%s'...", f.DisplayName(), t.Type(), t.Name()),
		fmt.Sprintf("Ending addition of feature '%s' on %s '%s'", f.DisplayName(), t.Type(), t.Name()),
	)()

	// 'v' may be updated by parallel tasks, so use copy of it
	myV := make(data.Map)
	for key, value := range v {
		myV[key] = value
	}

	// Inits implicit parameters
	err = f.setImplicitParameters(t, myV)
	if err != nil {
		return nil, err
	}

	// Checks required parameters have value
	err = checkParameters(f, myV)
	if err != nil {
		return nil, err
	}

	if !s.AddUnconditionally {
		results, err := f.Check(t, v, s)
		if err != nil {
			return nil, fmt.Errorf("failed to check feature '%s': %s", f.DisplayName(), err.Error())
		}
		if results.Successful() {
			logrus.Infof("Feature '%s' is already installed.", f.DisplayName())
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
		return nil, err
	}

	return results, err
}

// Remove uninstalls the feature from the target
func (f *Feature) Remove(t Target, v data.Map, s Settings) (_ Results, err error) {
	if f == nil {
		return nil, scerr.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(f.task, fmt.Sprintf("(): '%s' on %s '%s'", f.DisplayName(), t.Type(), t.Name()), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	var (
		results   Results
		installer Installer
	)
	methods := t.Methods()
	for _, meth := range methods {
		if f.specs.IsSet(fmt.Sprintf("feature.install.%s", strings.ToLower(meth.String()))) {
			installer = f.installerOfMethod(meth)
			if installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return nil, fmt.Errorf("failed to find a way to uninstall '%s'", f.DisplayName())
	}

	defer temporal.NewStopwatch().OnExitLogInfo(
		fmt.Sprintf("Starting removal of feature '%s' from %s '%s'", f.DisplayName(), t.Type(), t.Name()),
		fmt.Sprintf("Ending removal of feature '%s' from %s '%s'", f.DisplayName(), t.Type(), t.Name()),
	)()

	// 'v' may be updated by parallel tasks, so use copy of it
	myV := make(data.Map, len(v))
	for key, value := range v {
		myV[key] = value
	}

	// Inits implicit parameters
	err = f.setImplicitParameters(t, myV)
	if err != nil {
		return nil, err
	}

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
func (f *Feature) installRequirements(t Target, v data.Map, s Settings) error {
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
			logrus.Debugf("%s %s...\n", msgHead, msgTail)
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
func (f *Feature) setImplicitParameters(t Target, v data.Map) error {
	hT, cT, nT := determineContext(t)
	if cT != nil {
		cluster := cT.cluster
		networkCfg, err := cluster.GetNetworkConfig(f.task)
		if err != nil {
			return err
		}
		identity := cluster.GetIdentity(f.task)

		v["ClusterName"] = identity.Name
		v["ClusterComplexity"] = strings.ToLower(identity.Complexity.String())
		v["ClusterFlavor"] = strings.ToLower(identity.Flavor.String())
		v["PrimaryGatewayIP"] = networkCfg.GatewayIP
		v["DefaultRouteIP"] = networkCfg.DefaultRouteIP
		v["GatewayIP"] = v["DefaultRouteIP"] // legacy ...
		v["PrimaryPublicIP"] = networkCfg.PrimaryPublicIP
		if networkCfg.SecondaryGatewayIP != "" {
			v["SecondaryGatewayIP"] = networkCfg.SecondaryGatewayIP
		}
		v["SecondaryPublicIP"] = networkCfg.SecondaryPublicIP
		v["EndpointIP"] = networkCfg.EndpointIP
		v["PublicIP"] = v["EndpointIP"] // legacy ...
		if _, ok := v["CIDR"]; !ok {
			v["CIDR"] = networkCfg.CIDR
		}
		var controlPlaneV1 *clusterpropsv1.ControlPlane
		err = cluster.GetProperties(f.task).LockForRead(property.ControlPlaneV1).ThenUse(func(clonable data.Clonable) error {
			controlPlaneV1 = clonable.(*clusterpropsv1.ControlPlane)
			return nil
		})
		if err != nil {
			return err
		}
		if controlPlaneV1.VirtualIP != nil && controlPlaneV1.VirtualIP.PrivateIP != "" {
			v["ControlplaneUsesVIP"] = true
			v["ControlplaneEndpointIP"] = controlPlaneV1.VirtualIP.PrivateIP
		} else {
			// Don't set ControlplaneUsesVIP if there is no VIP...
			master, err := cluster.FindAvailableMaster(f.task)
			if err != nil {
				return err
			}
			host, err := cluster.GetService(f.task).InspectHost(master)
			if err != nil {
				return err
			}
			v["ControlplaneEndpointIP"] = host.GetPrivateIP()
		}

		nodeList, err := cluster.ListMasters(f.task)
		if err != nil {
			return err
		}
		v["ClusterMasters"] = nodeList
		list, err := cluster.ListMasterNames(f.task)
		if err != nil {
			return err
		}
		v["ClusterMasterNames"] = list.Values()
		list, err = cluster.ListMasterIDs(f.task)
		if err != nil {
			return err
		}
		v["ClusterMasterIDs"] = list.Values()
		list, err = cluster.ListMasterIPs(f.task)
		if err != nil {
			return err
		}
		v["ClusterMasterIPs"] = list.Values()
		nodeList, err = cluster.ListNodes(f.task)
		if err != nil {
			return err
		}
		v["ClusterNodes"] = nodeList
		list, err = cluster.ListNodeNames(f.task)
		if err != nil {
			return err
		}
		v["ClusterNodeNames"] = list.Values()
		list, err = cluster.ListNodeIDs(f.task)
		if err != nil {
			return err
		}
		v["ClusterNodeIDs"] = list.Values()
		list, err = cluster.ListNodeIPs(f.task)
		if err != nil {
			return err
		}
		v["ClusterNodeIPs"] = list.Values()
		v["ClusterAdminUsername"] = "cladm"
		v["ClusterAdminPassword"] = identity.AdminPassword
	} else {
		var host *pb.Host
		if nT != nil {
			host = nT.HostTarget.host
		}
		if hT != nil {
			host = hT.host
		}
		if host == nil {
			return scerr.InvalidParameterError("t", "must be a HostTarget or NodeTarget")
		}

		// FIXME: host may be on a network with 2 gateways + missing variables like DefaultRouteIP, ...
		gw := gatewayFromHost(host)
		if gw != nil {
			v["GatewayIP"] = gw.PrivateIp // legacy
			v["PrimaryGatewayIP"] = gw.PrivateIp
			v["PublicIP"] = gw.PublicIp
		} else {
			v["PublicIP"] = host.PublicIp
		}
		if _, ok := v["Username"]; !ok {
			v["Username"] = "safescale"
		}
	}

	return nil
}

// extractKeysAndValuesFromMap returns a slice with keys and a slice with values from map[uint]string
func extractKeysAndValuesFromMap(m map[uint]string) ([]uint, []string) {
	length := len(m)
	if length <= 0 {
		return []uint{}, []string{}
	}

	keys := make([]uint, 0, length)
	values := make([]string, 0, length)
	for k, v := range m {
		keys = append(keys, k)
		values = append(values, v)
	}
	return keys, values
}
