/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

package operations

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	rice "github.com/GeertJohan/go.rice"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusternodetype"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/remotefile"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

var (
	// templateBox is the rice box to use in this package
	clusterTemplateBox atomic.Value
)

// getTemplateBox
func getTemplateBox() (*rice.Box, error) {
	var (
		b   *rice.Box
		err error
	)
	anon := clusterTemplateBox.Load()
	if anon == nil {
		// Note: path MUST be literal for rice to work
		b, err = rice.FindBox("../operations/clusterflavors/scripts")
		if err != nil {
			return nil, err
		}
		clusterTemplateBox.Store(b)
		anon = clusterTemplateBox.Load()
	}
	return anon.(*rice.Box), nil
}

// TargetType returns the type of the target
//
// satisfies resources.Targetable interface
func (instance *cluster) TargetType() featuretargettype.Enum {
	return featuretargettype.CLUSTER
}

// InstallMethods returns a list of installation methods useable on the target, ordered from upper to lower preference (1 = highest preference)
// satisfies resources.Targetable interface
func (instance *cluster) InstallMethods(task concurrency.Task) map[uint8]installmethod.Enum {
	if instance.isNull() {
		logrus.Error(fail.InvalidInstanceError().Error())
		return nil
	}
	if task == nil {
		logrus.Errorf(fail.InvalidParameterCannotBeNilError("task").Error())
		return nil
	}
	if task.Aborted() {
		logrus.Error(fail.AbortedError(nil, "aborted").Error())
		return nil
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	if instance.installMethods == nil {
		instance.installMethods = map[uint8]installmethod.Enum{}
		var index uint8
		flavor, err := instance.unsafeGetFlavor(task)
		if err == nil && flavor == clusterflavor.K8S {
			index++
			instance.installMethods[index] = installmethod.Helm
		}
		index++
		instance.installMethods[index] = installmethod.Bash
		index++
		instance.installMethods[index] = installmethod.None
	}
	return instance.installMethods
}

// InstalledFeatures returns a list of installed features
func (instance *cluster) InstalledFeatures(task concurrency.Task) []string {
	var list []string
	return list
}

// ComplementFeatureParameters FIXME: include the cluster part of setImplicitParameters() from feature
// ComplementFeatureParameters configures parameters that are implicitly defined, based on target
// satisfies interface resources.Targetable
func (instance *cluster) ComplementFeatureParameters(task concurrency.Task, v data.Map) fail.Error {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	complexity, xerr := instance.GetComplexity(task)
	if xerr != nil {
		return xerr
	}

	v["ClusterComplexity"] = strings.ToLower(complexity.String())
	clusterFlavor, xerr := instance.GetFlavor(task)
	if xerr != nil {
		return xerr
	}

	v["ClusterFlavor"] = strings.ToLower(clusterFlavor.String())
	v["ClusterName"] = instance.GetName()
	v["ClusterAdminUsername"] = "cladm"
	if v["ClusterAdminPassword"], xerr = instance.GetAdminPassword(task); xerr != nil {
		return xerr
	}

	if _, ok := v["Username"]; !ok {
		v["Username"] = abstract.DefaultUser
	}
	networkCfg, xerr := instance.GetNetworkConfig(task)
	if xerr != nil {
		return xerr
	}

	v["PrimaryGatewayIP"] = networkCfg.GatewayIP
	v["DefaultRouteIP"] = networkCfg.DefaultRouteIP
	v["GatewayIP"] = v["DefaultRouteIP"] // legacy ...
	v["PrimaryPublicIP"] = networkCfg.PrimaryPublicIP
	v["NetworkUsesVIP"] = networkCfg.SecondaryGatewayIP != ""
	if networkCfg.SecondaryGatewayIP != "" {
		v["SecondaryGatewayIP"] = networkCfg.SecondaryGatewayIP
		v["SecondaryPublicIP"] = networkCfg.SecondaryPublicIP
	}
	v["EndpointIP"] = networkCfg.EndpointIP
	v["PublicIP"] = v["EndpointIP"] // legacy ...
	if _, ok := v["IPRanges"]; !ok {
		v["IPRanges"] = networkCfg.CIDR
	}
	v["CIDR"] = networkCfg.CIDR

	var controlPlaneV1 *propertiesv1.ClusterControlplane
	xerr = instance.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, clusterproperty.ControlPlaneV1, func(clonable data.Clonable) fail.Error {
			var ok bool
			controlPlaneV1, ok = clonable.(*propertiesv1.ClusterControlplane)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterControlplane' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	if controlPlaneV1.VirtualIP != nil && controlPlaneV1.VirtualIP.PrivateIP != "" {
		v["ClusterControlplaneUsesVIP"] = true
		v["ClusterControlplaneEndpointIP"] = controlPlaneV1.VirtualIP.PrivateIP
	} else {
		// Don't set ClusterControlplaneUsesVIP if there is no VIP... use IP of first available master instead
		master, xerr := instance.FindAvailableMaster(task)
		if xerr != nil {
			return xerr
		}

		if v["ClusterControlplaneEndpointIP"], xerr = master.GetPrivateIP(task); xerr != nil {
			return xerr
		}

		v["ClusterControlplaneUsesVIP"] = false
	}
	if v["ClusterMasters"], xerr = instance.ListMasters(task); xerr != nil {
		return xerr
	}

	if v["ClusterMasterNames"], xerr = instance.ListMasterNames(task); xerr != nil {
		return xerr
	}

	if v["ClusterMasterIDs"], xerr = instance.ListMasterIDs(task); xerr != nil {
		return xerr
	}

	if v["ClusterMasterIPs"], xerr = instance.ListMasterIPs(task); xerr != nil {
		return xerr
	}

	if v["ClusterNodes"], xerr = instance.ListNodes(task); xerr != nil {
		return xerr
	}

	if v["ClusterNodeNames"], xerr = instance.ListNodeNames(task); xerr != nil {
		return xerr
	}

	if v["ClusterNodeIDs"], xerr = instance.ListNodeIDs(task); xerr != nil {
		return xerr
	}

	if v["ClusterNodeIPs"], xerr = instance.ListNodeIPs(task); xerr != nil {
		return xerr
	}

	v["IPRanges"] = networkCfg.CIDR
	return nil
}

// RegisterFeature registers an installed Feature in metadata of a Cluster
// satisfies interface resources.Targetable
func (instance *cluster) RegisterFeature(task concurrency.Task, feat resources.Feature, requiredBy resources.Feature, _ bool) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if feat == nil {
		return fail.InvalidParameterError("feat", "cannot be null value of 'resources.Feature'")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			var item *propertiesv1.ClusterInstalledFeature
			if item, ok = featuresV1.Installed[feat.GetName()]; !ok {
				requirements, innerXErr := feat.GetRequirements()
				if innerXErr != nil {
					return innerXErr
				}

				item = propertiesv1.NewClusterInstalledFeature()
				item.Requires = requirements
				featuresV1.Installed[feat.GetName()] = item
			}
			if rf, ok := requiredBy.(*feature); ok && !rf.isNull() {
				item.RequiredBy[rf.GetName()] = struct{}{}
			}
			return nil
		})
	})
}

// UnregisterFeature unregisters a Feature from Cluster metadata
// satisfies interface resources.Targetable
func (instance *cluster) UnregisterFeature(task concurrency.Task, feat string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if feat == "" {
		return fail.InvalidParameterError("feat", "cannot be empty string")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			delete(featuresV1.Installed, feat)
			for _, v := range featuresV1.Installed {
				delete(v.RequiredBy, feat)
			}
			return nil
		})
	})
}

// ListInstalledFeatures returns a slice of installed features
func (instance *cluster) ListInstalledFeatures(task concurrency.Task) ([]resources.Feature, fail.Error) {
	var emptySlice []resources.Feature
	if instance.isNull() {
		return emptySlice, fail.InvalidInstanceError()
	}
	if task == nil {
		return emptySlice, fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return emptySlice, fail.AbortedError(nil, "aborted")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	var list map[string]*propertiesv1.ClusterInstalledFeature
	xerr := instance.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			list = featuresV1.Installed
			return nil
		})
	})
	if xerr != nil {
		return emptySlice, xerr
	}

	out := make([]resources.Feature, 0, len(list))
	for k := range list {
		item, xerr := NewFeature(task, instance.GetService(), k)
		if xerr != nil {
			return emptySlice, xerr
		}

		out = append(out, item)
	}
	return out, nil
}

// AddFeature installs a feature on the cluster
func (instance *cluster) AddFeature(task concurrency.Task, name string, vars data.Map, settings resources.FeatureSettings) (resources.Results, fail.Error) {
	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	feat, xerr := NewFeature(task, instance.GetService(), name)
	if xerr != nil {
		return nil, xerr
	}

	return feat.Add(instance, vars, settings)
}

// CheckFeature tells if a feature is installed on the cluster
func (instance *cluster) CheckFeature(task concurrency.Task, name string, vars data.Map, settings resources.FeatureSettings) (resources.Results, fail.Error) {
	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	feat, xerr := NewFeature(task, instance.GetService(), name)
	if xerr != nil {
		return nil, xerr
	}

	return feat.Check(instance, vars, settings)
}

// RemoveFeature uninstalls a feature from the cluster
func (instance *cluster) RemoveFeature(task concurrency.Task, name string, vars data.Map, settings resources.FeatureSettings) (resources.Results, fail.Error) {
	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	feat, xerr := NewFeature(task, instance.GetService(), name)
	if xerr != nil {
		return nil, xerr
	}

	return feat.Remove(instance, vars, settings)
}

// ExecuteScript executes the script template with the parameters on target Host
func (instance *cluster) ExecuteScript(task concurrency.Task, tmplName string, data map[string]interface{}, host resources.Host) (_ int, _ string, _ string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return -1, "", "", fail.InvalidInstanceError()
	}
	if task == nil {
		return -1, "", "", fail.InvalidParameterCannotBeNilError("task")
	}
	if tmplName == "" {
		return -1, "", "", fail.InvalidParameterError("tmplName", "cannot be empty string")
	}
	if host == nil {
		return -1, "", "", fail.InvalidParameterCannotBeNilError("host")
	}

	if task.Aborted() {
		return -1, "", "", fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "('%s')", host.GetName()).Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	box, err := getTemplateBox()
	if err != nil {
		return 0, "", "", fail.ConvertError(err)
	}

	// Configures reserved_BashLibrary template var
	bashLibrary, xerr := system.GetBashLibrary()
	if xerr != nil {
		return -1, "", "", xerr
	}
	data["reserved_BashLibrary"] = bashLibrary

	// Sets delays and timeouts for script
	data["reserved_DefaultDelay"] = uint(math.Ceil(2 * temporal.GetDefaultDelay().Seconds()))
	data["reserved_DefaultTimeout"] = strings.Replace(
		(temporal.GetHostTimeout() / 2).Truncate(time.Minute).String(), "0s", "", -1,
	)
	data["reserved_LongTimeout"] = strings.Replace(
		temporal.GetHostTimeout().Truncate(time.Minute).String(), "0s", "", -1,
	)
	data["reserved_DockerImagePullTimeout"] = strings.Replace(
		(2 * temporal.GetHostTimeout()).Truncate(time.Minute).String(), "0s", "", -1,
	)

	script, path, xerr := realizeTemplate(box, tmplName, data, tmplName)
	if xerr != nil {
		return -1, "", "", fail.Wrap(xerr, "failed to realize template '%s'", tmplName)
	}

	hidesOutput := strings.Contains(script, "set +x\n")
	if hidesOutput {
		script = strings.Replace(script, "set +x\n", "\n", 1)
		if strings.Contains(script, "exec 2>&1\n") {
			script = strings.Replace(script, "exec 2>&1\n", "exec 2>&7\n", 1)
		}
	}

	// Uploads the script into remote file
	rfcItem := remotefile.Item{Remote: path}
	xerr = rfcItem.UploadString(task, script, host)
	_ = os.Remove(rfcItem.Local)
	if xerr != nil {
		return -1, "", "", xerr
	}

	// executes remote file
	var cmd string
	if hidesOutput {
		//		cmd = fmt.Sprintf("sudo chmod u+rx %s;sudo bash -instance \"BASH_XTRACEFD=7 %s 7>/tmp/captured 2>&7\";retcode=${PIPESTATUS};cat /tmp/captured; sudo rm /tmp/captured;exit ${retcode}", path, path)
		cmd = fmt.Sprintf("sudo -- bash -instance 'chmod u+rx %s; captf=$(mktemp); bash -instance \"BASH_XTRACEFD=7 %s 7>$captf 2>&7\"; rc=${PIPESTATUS}; cat $captf; rm $captf; exit ${rc}'", path, path)
	} else {
		//		cmd = fmt.Sprintf("sudo chmod u+rx %s;sudo bash %s;exit ${PIPESTATUS}", path, path)
		cmd = fmt.Sprintf("sudo -- bash -instance 'chmod u+rx %s; bash -instance %s; exit ${PIPESTATUS}'", path, path)
	}
	return host.Run(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), 2*temporal.GetLongOperationTimeout())
}

// installNodeRequirements ...
func (instance *cluster) installNodeRequirements(task concurrency.Task, nodeType clusternodetype.Enum, host resources.Host, hostLabel string) (xerr fail.Error) {
	// tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
	// defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	netCfg, xerr := instance.GetNetworkConfig(task)
	if xerr != nil {
		return xerr
	}

	params := data.Map{}
	if nodeType == clusternodetype.Master {
		tp := instance.GetService().GetTenantParameters()
		content := map[string]interface{}{
			"tenants": []map[string]interface{}{tp},
		}
		jsoned, err := json.MarshalIndent(content, "", "    ")
		if err != nil {
			return fail.ConvertError(err)
		}
		params["reserved_TenantJSON"] = string(jsoned)

		// Finds the folder where the current binary resides
		var (
			exe       string
			binaryDir string
			path      string
		)
		exe, _ = os.Executable()
		if exe != "" {
			binaryDir = filepath.Dir(exe)
		}

		// Uploads safescale binary
		if binaryDir != "" {
			path = binaryDir + "/safescale"
		}
		if path == "" {
			path, err = exec.LookPath("safescale")
			if err != nil {
				return fail.Wrap(err, "failed to find local binary 'safescale', make sure its path is in environment variable PATH")
			}
		}

		retcode, stdout, stderr, xerr := host.Push(task, path, "/opt/safescale/bin/safescale", "root:root", "0755", temporal.GetExecutionTimeout())
		if xerr != nil {
			return fail.Wrap(xerr, "failed to upload 'safescale' binary")
		}
		if retcode != 0 {
			output := stdout
			if output != "" && stderr != "" {
				output += "\n" + stderr
			} else if stderr != "" {
				output = stderr
			}
			return fail.NewError("failed to copy safescale binary to '%s:/opt/safescale/bin/safescale': retcode=%d, output=%s", host.GetName(), retcode, output)
		}

		// Uploads safescaled binary
		path = ""
		if binaryDir != "" {
			path = binaryDir + "/safescaled"
		}
		if path == "" {
			path, err = exec.LookPath("safescaled")
			if err != nil {
				return fail.Wrap(err, "failed to find local binary 'safescaled', make sure its path is in environment variable PATH")
			}
		}
		if retcode, stdout, stderr, xerr = host.Push(task, path, "/opt/safescale/bin/safescaled", "root:root", "0755", temporal.GetExecutionTimeout()); xerr != nil {
			return fail.Wrap(xerr, "failed to submit content of 'safescaled' binary to host '%s'", host.GetName())
		}
		if retcode != 0 {
			output := stdout
			if output != "" && stderr != "" {
				output += "\n" + stderr
			} else if stderr != "" {
				output = stderr
			}
			return fail.NewError("failed to copy safescaled binary to '%s:/opt/safescale/bin/safescaled': retcode=%d, output=%s", host.GetName(), retcode, output)
		}
		// Optionally propagate SAFESCALE_METADATA_SUFFIX env vars to master
		if suffix := os.Getenv("SAFESCALE_METADATA_SUFFIX"); suffix != "" {
			cmdTmpl := "sudo sed -i '/^SAFESCALE_METADATA_SUFFIX=/{h;s/=.*/=%s/};${x;/^$/{s//SAFESCALE_METADATA_SUFFIX=%s/;H};x}' /etc/environment"
			cmd := fmt.Sprintf(cmdTmpl, suffix, suffix)
			retcode, stdout, stderr, xerr := host.Run(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), 2*temporal.GetLongOperationTimeout())
			if xerr != nil {
				return fail.Wrap(xerr, "failed to submit content of SAFESCALE_METADATA_SUFFIX to Host '%s'", host.GetName())
			}
			if retcode != 0 {
				output := stdout
				if output != "" && stderr != "" {
					output += "\n" + stderr
				} else if stderr != "" {
					output = stderr
				}
				msg := fmt.Sprintf("failed to copy content of SAFESCALE_METADATA_SUFFIX to Host '%s': %s", host.GetName(), output)
				return fail.NewError(strprocess.Capitalize(msg))
			}
		}
	}

	var dnsServers []string
	cfg, xerr := instance.GetService().GetConfigurationOptions()
	if xerr == nil {
		dnsServers = cfg.GetSliceOfStrings("DNSList")
	}
	identity, xerr := instance.unsafeGetIdentity(task)
	if xerr != nil {
		return xerr
	}

	params["ClusterName"] = identity.Name
	params["DNSServerIPs"] = dnsServers
	if params["MasterIPs"], xerr = instance.unsafeListMasterIPs(task); xerr != nil {
		return xerr
	}

	params["ClusterAdminUsername"] = "cladm"
	params["ClusterAdminPassword"] = identity.AdminPassword
	params["DefaultRouteIP"] = netCfg.DefaultRouteIP
	params["EndpointIP"] = netCfg.EndpointIP
	params["IPRanges"] = netCfg.CIDR
	params["SSHPublicKey"] = identity.Keypair.PublicKey
	params["SSHPrivateKey"] = identity.Keypair.PrivateKey

	if _, _, _, xerr = instance.ExecuteScript(task, "node_install_requirements.sh", params, host); xerr != nil {
		return fail.Wrap(xerr, "[%s] system requirements installation failed", hostLabel)
	}

	logrus.Debugf("[%s] system requirements installation successful.", hostLabel)
	return nil
}

// Installs reverseproxy
func (instance *cluster) installReverseProxy(task concurrency.Task) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	identity, xerr := instance.unsafeGetIdentity(task)
	if xerr != nil {
		return xerr
	}
	clusterName := identity.Name

	// tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
	// defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	disabled := false
	xerr = instance.Review(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			_, disabled = featuresV1.Disabled["reverseproxy"]
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	if !disabled {
		logrus.Debugf("[cluster %s] adding feature 'edgeproxy4subnet'", clusterName)
		feat, xerr := NewFeature(task, instance.GetService(), "edgeproxy4subnet")
		if xerr != nil {
			return xerr
		}

		results, xerr := feat.Add(instance, data.Map{}, resources.FeatureSettings{})
		if xerr != nil {
			return xerr
		}

		if !results.Successful() {
			msg := results.AllErrorMessages()
			return fail.NewError("[cluster %s] failed to add '%s': %s", clusterName, feat.GetName(), msg)
		}
		logrus.Debugf("[cluster %s] feature '%s' added successfully", clusterName, feat.GetName())
		return nil
	}

	logrus.Infof("[cluster %s] reverseproxy (feature 'edgeproxy4subnet' not installed because disabled", clusterName)
	return nil
}

// installRemoteDesktop installs feature remotedesktop on all masters of the cluster
func (instance *cluster) installRemoteDesktop(task concurrency.Task) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	identity, xerr := instance.unsafeGetIdentity(task)
	if xerr != nil {
		return xerr
	}

	// clusterName := identity.Name

	// tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
	// defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	disabled := false
	xerr = instance.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			_, disabled = featuresV1.Disabled["remotedesktop"]
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	if !disabled {
		logrus.Debugf("[cluster %s] adding feature 'remotedesktop'", identity.Name)

		feat, xerr := NewFeature(task, instance.GetService(), "remotedesktop")
		if xerr != nil {
			return xerr
		}

		// Adds remotedesktop feature on cluster (ie masters)
		vars := data.Map{
			"Username": "cladm",
			"Password": identity.AdminPassword,
		}
		r, xerr := feat.Add(instance, vars, resources.FeatureSettings{})
		if xerr != nil {
			return xerr
		}

		if !r.Successful() {
			msg := r.AllErrorMessages()
			return fail.NewError("[cluster %s] failed to add 'remotedesktop' failed: %s", identity.Name, msg)
		}
		logrus.Debugf("[cluster %s] feature 'remotedesktop' added successfully", identity.Name)
	}
	return nil
}

// install proxycache-client feature if not disabled
func (instance *cluster) installProxyCacheClient(task concurrency.Task, host resources.Host, hostLabel string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if host == nil {
		return fail.InvalidParameterCannotBeNilError("host")
	}
	if hostLabel == "" {
		return fail.InvalidParameterError("hostLabel", "cannot be empty string")
	}

	// tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
	// defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	disabled := false
	xerr = instance.Review(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			_, disabled = featuresV1.Disabled["proxycache"]
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}
	if !disabled {
		feat, xerr := NewFeature(task, instance.GetService(), "proxycache-client")
		if xerr != nil {
			return xerr
		}

		r, xerr := feat.Add(host, data.Map{}, resources.FeatureSettings{})
		if xerr != nil {
			return xerr
		}

		if !r.Successful() {
			msg := r.AllErrorMessages()
			return fail.NewError("[%s] failed to install feature 'proxycache-client': %s", hostLabel, msg)
		}
	}
	return nil
}

// install proxycache-server feature if not disabled
func (instance *cluster) installProxyCacheServer(task concurrency.Task, host resources.Host, hostLabel string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if host == nil {
		return fail.InvalidParameterCannotBeNilError("host")
	}
	if hostLabel == "" {
		return fail.InvalidParameterError("hostLabel", "cannot be empty string")
	}

	// tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
	// defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	disabled := false
	xerr = instance.Review(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			_, disabled = featuresV1.Disabled["proxycache"]
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	if !disabled {
		feat, xerr := NewFeature(task, instance.GetService(), "proxycache-server")
		if xerr != nil {
			return xerr
		}

		r, xerr := feat.Add(host, data.Map{}, resources.FeatureSettings{})
		if xerr != nil {
			return xerr
		}

		if !r.Successful() {
			msg := r.AllErrorMessages()
			return fail.NewError("[%s] failed to install feature 'proxycache-server': %s", hostLabel, msg)
		}
	}
	return nil
}

// intallDocker installs docker and docker-compose
func (instance *cluster) installDocker(task concurrency.Task, host resources.Host, hostLabel string) (xerr fail.Error) {
	// if host == nil {
	// 	return fail.InvalidParameterCannotBeNilError("host")
	// }
	// if hostLabel == "" {
	// 	return fail.InvalidParameterError("hostLabel", "cannot be empty string")
	// }

	// tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
	// defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	// uses NewFeature() to let a chance to the user to use it's own docker feature
	feat, xerr := NewFeature(task, instance.GetService(), "docker")
	if xerr != nil {
		return xerr
	}

	r, xerr := feat.Add(host, data.Map{}, resources.FeatureSettings{})
	if xerr != nil {
		return xerr
	}

	if !r.Successful() {
		msg := r.AllErrorMessages()
		logrus.Errorf("[%s] failed to add feature 'docker': %s", hostLabel, msg)
		return fail.NewError("failed to add feature 'docker': %s", host.GetName(), msg)
	}
	logrus.Debugf("[%s] feature 'docker' addition successful.", hostLabel)
	return nil
}
