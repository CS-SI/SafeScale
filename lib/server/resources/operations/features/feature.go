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

package features

import (
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
	networkfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/network"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// feature contains the information about an installable feature
type feature struct {
	// displayName is the name of the service
	displayName string
	// fileName is the name of the specification file
	fileName string
	// embedded tells if the feature is embedded in deploy
	embedded bool
	// Installers defines the installers available for the feature
	installers map[installmethod.Enum]Installer
	// Dependencies lists other feature(s) (by name) needed by this one
	//dependencies []string
	// Management contains a string map of data that could be used to manage the feature (if it makes sense)
	// This could be used to explain to Service object how to manage the feature, to react as a service
	//Management map[string]interface{}
	// specs is the Viper instance containing feature specification
	specs *viper.Viper
	task  concurrency.Task
}

// List lists all features suitable for hosts or clusters
func List(task concurrency.Task, suitableFor string) ([]interface{}, error) {
	if task == nil {
		return nil, scerr.InvalidInstanceError()
	}

	features := allEmbeddedMap
	var cfgFiles []interface{}

	var paths []string
	paths = append(paths, utils.AbsPathify("$HOME/.safescale/features"))
	paths = append(paths, utils.AbsPathify("$HOME/.config/safescale/features"))
	paths = append(paths, utils.AbsPathify("/etc/safescale/features"))

	for _, path := range paths {
		files, err := ioutil.ReadDir(path)
		if err == nil {
			for _, f := range files {
				if strings.HasSuffix(strings.ToLower(f.Name()), ".yml") {
					feat, err := New(task, strings.Replace(strings.ToLower(f.Name()), ".yml", "", 1))
					if err != nil {
						logrus.Error(err) // FIXME Don't hide errors
						continue
					}
					casted := feat.(*feature)
					if _, ok := allEmbeddedMap[casted.displayName]; !ok {
						allEmbeddedMap[casted.displayName] = casted
					}
				}
			}
		}
	}

	for _, feat := range features {
		switch suitableFor {
		case "host":
			yamlKey := "feature.suitableFor.host"
			if feat.Specs().IsSet(yamlKey) {
				value := strings.ToLower(feat.Specs().GetString(yamlKey))
				if value == "ok" || value == "yes" || value == "true" || value == "1" {
					cfgFiles = append(cfgFiles, feat.fileName)
				}
			}
		case "cluster":
			yamlKey := "feature.suitableFor.cluster"
			if feat.Specs().IsSet(yamlKey) {
				values := strings.Split(strings.ToLower(feat.Specs().GetString(yamlKey)), ",")
				if values[0] == "all" || values[0] == "dcos" || values[0] == "k8s" || values[0] == "boh" || values[0] == "swarm" || values[0] == "ohpc" {
					cfg := struct {
						FeatureName    string   `json:"feature"`
						ClusterFlavors []string `json:"available-cluster-flavors"`
					}{feat.displayName, []string{}}

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

// New searches for a spec file name 'name' and initializes a new Feature object
// with its content
// error contains :
//    - *scerr.ErrNotFound if no feature is found by its name
//    - *scerr.ErrSyntax if feature found contains syntax error
func New(task concurrency.Task, name string) (_ resources.Feature, err error) {
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

	var casted *feature
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
				casted = allEmbeddedMap[name].Clone().(*feature)
				casted.task = task
			}
		default:
			err = scerr.SyntaxError(fmt.Sprintf("failed to read the specification file of feature called '%s': %s", name, err.Error()))
		}
	} else if v.IsSet("feature") {
		casted = &feature{
			fileName:    name + ".yml",
			displayName: name,
			specs:       v,
			task:        task,
		}
	}
	return casted, err
}

// NewEmbedded searches for an embedded featured named 'name' and initializes a new Feature object
// with its content
func NewEmbedded(task concurrency.Task, name string) (_ resources.Feature, err error) {
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	var casted *feature
	if _, ok := allEmbeddedMap[name]; !ok {
		err = scerr.NotFoundError(fmt.Sprintf("failed to find a feature named '%s'", name))
	} else {
		casted = allEmbeddedMap[name].Clone().(*feature)
		casted.task = task
	}
	return casted, err
}

// Clone ...
// satisfies interface data.Clonable
func (f *feature) Clone() data.Clonable {
	res := &feature{}
	return res.Replace(f)
}

// Replace ...
// satisfies interface data.Clonable
func (f *feature) Replace(p data.Clonable) data.Clonable {
	src := p.(*feature)
	*f = *src
	f.installers = make(map[installmethod.Enum]Installer, len(src.installers))
	for k, v := range src.installers {
		f.installers[k] = v
	}
	return f
}

// installerOfMethod instanciates the right installer corresponding to the method
func (f *feature) installerOfMethod(m installmethod.Enum) Installer {
	var installer Installer
	switch m {
	case installmethod.Bash:
		installer = NewBashInstaller()
	case installmethod.Apt:
		installer = NewAptInstaller()
	case installmethod.Yum:
		installer = NewYumInstaller()
	case installmethod.Dnf:
		installer = NewDnfInstaller()
	}
	return installer
}

// Name returns the name of the feature
func (f *feature) Name() string {
	return f.displayName
}

// Filename returns the name of the feature
func (f *feature) Filename() string {
	return f.displayName
}

// DisplayFilename returns the full file name, with [embedded] added at the end if the
// feature is embedded.
func (f *feature) DisplayFilename() string {
	filename := f.fileName
	if f.embedded {
		filename += " [embedded]"
	}
	return filename
}

// Specs returns a copy of the spec file (we don't want external use to modify Feature.specs)
func (f *feature) Specs() *viper.Viper {
	roSpecs := *f.specs
	return &roSpecs
}

// Applyable tells if the feature is installable on the target
func (f *feature) Applyable(t resources.Targetable) bool {
	methods := t.InstallMethods(f.task)
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
func (f *feature) Check(t resources.Targetable, v data.Map, s resources.FeatureSettings) (_ resources.Results, err error) {
	if f == nil {
		return nil, scerr.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(f.task, fmt.Sprintf("(): '%s' on %s '%s'", f.Name(), t.TargetType().String(), t.Name()), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	// cacheKey := f.DisplayName() + "@" + t.Name()
	// if anon, ok := checkCache.Get(cacheKey); ok {
	// 	return anon.(Results), nil
	// }

	methods := t.InstallMethods(f.task)
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
		return nil, fmt.Errorf("failed to find a way to check '%s'", f.Name())
	}

	logrus.Debugf("Checking if feature '%s' is installed on %s '%s'...\n", f.Name(), t.TargetType().String(), t.Name())

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

	results, err := installer.Check(f, t, myV, s)
	// _ = checkCache.ForceSet(cacheKey, results)
	return results, err
}

// Check if required parameters defined in specification file have been set in 'v'
func checkParameters(f *feature, v data.Map) error {
	if f.specs.IsSet("feature.parameters") {
		params := f.specs.GetStringSlice("feature.parameters")
		for _, k := range params {
			splitted := strings.Split(k, "=")
			if _, ok := v[splitted[0]]; !ok {
				if len(splitted) == 1 {
					return fmt.Errorf("missing value for parameter '%s'", k)
				}
				v[splitted[0]] = strings.Join(splitted[1:], "=")
			}
		}
	}
	return nil
}

// Add installs the feature on the target
// Installs succeeds if error == nil and Results.Successful() is true
func (f *feature) Add(t resources.Targetable, v data.Map, s resources.FeatureSettings) (_ resources.Results, err error) {
	if f == nil {
		return nil, scerr.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(f.task, fmt.Sprintf("(): '%s' on %s '%s'", f.Name(), t.TargetType().String(), t.Name()), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	methods := t.InstallMethods(f.task)
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
		return nil, fmt.Errorf("failed to find a way to install '%s'", f.Name())
	}

	defer temporal.NewStopwatch().OnExitLogInfo(
		fmt.Sprintf("Starting addition of feature '%s' on %s '%s'...", f.Name(), t.TargetType().String(), t.Name()),
		fmt.Sprintf("Ending addition of feature '%s' on %s '%s'", f.Name(), t.TargetType().String(), t.Name()),
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

	if !s.AddUnconditionally {
		results, err := f.Check(t, v, s)
		if err != nil {
			return nil, fmt.Errorf("failed to check feature '%s': %s", f.Name(), err.Error())
		}
		if results.Successful() {
			logrus.Infof("Feature '%s' is already installed.", f.Name())
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
func (f *feature) Remove(t resources.Targetable, v data.Map, s resources.FeatureSettings) (_ resources.Results, err error) {
	if f == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if t == nil {
		return nil, scerr.InvalidParameterError("t", "cannot be nil")
	}

	tracer := concurrency.NewTracer(f.task, fmt.Sprintf("(): '%s' on %s '%s'", f.Name(), t.TargetType().String(), t.Name()), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	var (
		results   resources.Results
		installer Installer
	)
	methods := t.InstallMethods(f.task)
	for _, meth := range methods {
		if f.specs.IsSet(fmt.Sprintf("feature.install.%s", strings.ToLower(meth.String()))) {
			installer = f.installerOfMethod(meth)
			if installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return nil, fmt.Errorf("failed to find a way to uninstall '%s'", f.Name())
	}

	defer temporal.NewStopwatch().OnExitLogInfo(
		fmt.Sprintf("Starting removal of feature '%s' from %s '%s'", f.Name(), t.TargetType().String(), t.Name()),
		fmt.Sprintf("Ending removal of feature '%s' from %s '%s'", f.Name(), t.TargetType().String(), t.Name()),
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
func (f *feature) installRequirements(t resources.Targetable, v data.Map, s resources.FeatureSettings) error {
	yamlKey := "feature.requirements.features"
	if f.specs.IsSet(yamlKey) {
		{
			msgHead := fmt.Sprintf("Checking requirements of feature '%s'", f.Name())
			var msgTail string
			switch t.TargetType() {
			case "host":
				msgTail = fmt.Sprintf("on host '%s'", t.(data.Identifyable).Name())
			case "node":
				msgTail = fmt.Sprintf("on cluster node '%s'", t.(data.Identifyable).Name())
			case "cluster":
				msgTail = fmt.Sprintf("on cluster '%s'", t.(data.Identifyable).Name())
			}
			logrus.Debugf("%s %s...", msgHead, msgTail)
		}
		for _, requirement := range f.specs.GetStringSlice(yamlKey) {
			needed, err := New(f.task, requirement)
			if err != nil {
				return fmt.Errorf("failed to find required feature '%s': %s", requirement, err.Error())
			}
			results, err := needed.Check(t, v, s)
			if err != nil {
				return fmt.Errorf("failed to check required feature '%s' for feature '%s': %s", requirement, f.Name(), err.Error())
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
func (f *feature) setImplicitParameters(t resources.Targetable, v data.Map) error {
	if t == nil {
		return scerr.InvalidParameterError("t", "must be a 'resources.Targetable'")
	}

	if t.TargetType() == featuretargettype.CLUSTER {
		cluster := t.(resources.Cluster)
		identity, err := cluster.Identity(f.task)
		if err != nil {
			return err
		}
		v["ClusterName"] = identity.Name
		v["ClusterComplexity"] = strings.ToLower(identity.Complexity.String())
		v["ClusterFlavor"] = strings.ToLower(identity.Flavor.String())
		networkCfg, err := cluster.NetworkConfig(f.task)
		if err != nil {
			return err
		}
		v["PrimaryGatewayIP"] = networkCfg.GatewayIP
		v["DefaultRouteIP"] = networkCfg.DefaultRouteIP
		v["GatewayIP"] = v["DefaultRouteIP"] // legacy ...
		v["PrimaryPublicIP"] = networkCfg.PrimaryPublicIP
		if networkCfg.SecondaryGatewayIP != "" {
			v["SecondaryGatewayIP"] = networkCfg.SecondaryGatewayIP
			v["SecondaryPublicIP"] = networkCfg.SecondaryPublicIP
		}
		v["EndpointIP"] = networkCfg.EndpointIP
		v["PublicIP"] = v["EndpointIP"] // legacy ...
		if _, ok := v["CIDR"]; !ok {
			v["CIDR"] = networkCfg.CIDR
		}
		var controlPlaneV1 *propertiesv1.ClusterControlPlane
		err = cluster.Inspect(f.task, func(_ data.Clonable, props *serialize.JSONProperties) error {
			return props.Inspect(clusterproperty.ControlPlaneV1, func(clonable data.Clonable) error {
				var ok bool
				controlPlaneV1, ok = clonable.(*propertiesv1.ClusterControlPlane)
				if !ok {
					return scerr.InconsistentError("'*propertiesv1.ClusterControlPlane' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				return nil
			})
		})
		if err != nil {
			return err
		}
		if controlPlaneV1.VirtualIP != nil && controlPlaneV1.VirtualIP.PrivateIP != "" {
			v["ClusterControlPlaneUsesVIP"] = true
			v["ClusterControlPlaneEndpointIP"] = controlPlaneV1.VirtualIP.PrivateIP
		} else {
			// Don't set ControlplaneUsesVIP if there is no VIP... use IP of first available master instead
			master, err := cluster.FindAvailableMaster(f.task)
			if err != nil {
				return err
			}

			v["ClusterControlPlaneEndpointIP"], err = master.PrivateIP(f.task)
			if err != nil {
				return err
			}
			v["ClusterControlPlaneUsesVIP"] = false
		}
		v["ClusterMasters"], err = cluster.ListMasters(f.task)
		if err != nil {
			return err
		}
		v["ClusterMasterNames"], err = cluster.ListMasterNames(f.task)
		if err != nil {
			return err
		}
		v["ClusterMasterIDs"], err = cluster.ListMasterIDs(f.task)
		if err != nil {
			return err
		}
		v["ClusterMasterIPs"], err = cluster.ListMasterIPs(f.task)
		if err != nil {
			return err
		}
		v["ClusterNodes"], err = cluster.ListNodes(f.task)
		if err != nil {
			return err
		}
		v["ClusterNodeNames"], err = cluster.ListNodeNames(f.task)
		if err != nil {
			return err
		}
		v["ClusterNodeIDs"], err = cluster.ListNodeIDs(f.task)
		if err != nil {
			return err
		}
		v["ClusterNodeIPs"], err = cluster.ListNodeIPs(f.task)
		if err != nil {
			return err
		}
		v["ClusterAdminUsername"] = "cladm"
		v["ClusterAdminPassword"] = identity.AdminPassword
	} else {
		host := t.(resources.Host)
		var network resources.Network

		err := host.Inspect(f.task, func(_ data.Clonable, props *serialize.JSONProperties) error {
			return props.Inspect(hostproperty.NetworkV1, func(clonable data.Clonable) error {
				var innerErr error
				networkV1, ok := clonable.(*propertiesv1.HostNetwork)
				if !ok {
					return scerr.InconsistentError("'*propertiesv1.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				network, innerErr = networkfactory.Load(f.task, host.Service(), networkV1.DefaultNetworkID)
				if innerErr != nil {
					return innerErr
				}
				return nil
			})
		})
		if err != nil {
			return err
		}
		gw, innerErr := network.Gateway(f.task, true)
		if err != nil {
			return err
		}
		if v["PrimaryGatewayIP"], err = gw.PrivateIP(f.task); err != nil {
			return err
		}
		v["GatewayIP"] = v["PrimaryGatewayIP"] // legacy
		if v["PrimaryPublicIP"], err = gw.PublicIP(f.task); err != nil {
			return err
		}
		gw, innerErr = network.Gateway(f.task, false)
		if innerErr == nil {
			if v["SecondaryGatewayIP"], innerErr = gw.PrivateIP(f.task); innerErr != nil {
				return innerErr
			}
			if v["SecondaryPublicIP"], innerErr = gw.PublicIP(f.task); innerErr != nil {
				return innerErr
			}
		} else if _, ok := innerErr.(*scerr.ErrNotFound); !ok {
			return innerErr
		}
		if v["EndpointIP"], err = network.EndpointIP(f.task); err != nil {
			return err
		}
		if v["DefaultRouteIP"], err = network.DefaultRouteIP(f.task); err != nil {
			return err
		}
		if _, ok := v["Username"]; !ok {
			v["Username"] = "safescale"
		}
	}

	return nil
}
