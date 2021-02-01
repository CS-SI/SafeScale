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
func (c *cluster) TargetType() featuretargettype.Enum {
	return featuretargettype.CLUSTER
}

// InstallMethods returns a list of installation methods useable on the target, ordered from upper to lower preference (1 = highest preference)
// satisfies feature.Targetable interface
func (c *cluster) InstallMethods(task concurrency.Task) map[uint8]installmethod.Enum {
	if c == nil {
		logrus.Error(fail.InvalidInstanceError().Error())
		return nil
	}
	if task.IsNull() {
		logrus.Errorf(fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'").Error())
		return nil
	}

	c.SafeLock(task)
	defer c.SafeUnlock(task)

	if c.installMethods == nil {
		c.installMethods = map[uint8]installmethod.Enum{}
		var index uint8
		flavor, err := c.GetFlavor(task)
		if err == nil && flavor == clusterflavor.K8S {
			index++
			c.installMethods[index] = installmethod.Helm
		}
		index++
		c.installMethods[index] = installmethod.Bash
	}
	return c.installMethods
}

// InstalledFeatures returns a list of installed features
func (c *cluster) InstalledFeatures(task concurrency.Task) []string {
	var list []string
	return list
}

// FIXME: include the cluster part of setImplicitParameters() from feature
// ComplementFeatureParameters configures parameters that are implicitely defined, based on target
func (c *cluster) ComplementFeatureParameters(task concurrency.Task, v data.Map) fail.Error {
	if c == nil {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}

	complexity, xerr := c.GetComplexity(task)
	if xerr != nil {
		return xerr
	}
	v["ClusterComplexity"] = strings.ToLower(complexity.String())
	clusterFlavor, xerr := c.GetFlavor(task)
	if xerr != nil {
		return xerr
	}
	v["ClusterFlavor"] = strings.ToLower(clusterFlavor.String())
	v["ClusterName"] = c.GetName()
	v["ClusterAdminUsername"] = "cladm"
	if v["ClusterAdminPassword"], xerr = c.GetAdminPassword(task); xerr != nil {
		return xerr
	}
	if _, ok := v["Username"]; !ok {
		v["Username"] = abstract.DefaultUser
	}

	networkCfg, xerr := c.GetNetworkConfig(task)
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
	xerr = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
		master, xerr := c.FindAvailableMaster(task)
		if xerr != nil {
			return xerr
		}
		if v["ClusterControlplaneEndpointIP"], xerr = master.GetPrivateIP(task); xerr != nil {
			return xerr
		}
		v["ClusterControlplaneUsesVIP"] = false
	}
	if v["ClusterMasters"], xerr = c.ListMasters(task); xerr != nil {
		return xerr
	}
	if v["ClusterMasterNames"], xerr = c.ListMasterNames(task); xerr != nil {
		return xerr
	}
	if v["ClusterMasterIDs"], xerr = c.ListMasterIDs(task); xerr != nil {
		return xerr
	}
	if v["ClusterMasterIPs"], xerr = c.ListMasterIPs(task); xerr != nil {
		return xerr
	}
	if v["ClusterNodes"], xerr = c.ListNodes(task); xerr != nil {
		return xerr
	}
	if v["ClusterNodeNames"], xerr = c.ListNodeNames(task); xerr != nil {
		return xerr
	}
	if v["ClusterNodeIDs"], xerr = c.ListNodeIDs(task); xerr != nil {
		return xerr
	}
	if v["ClusterNodeIPs"], xerr = c.ListNodeIPs(task); xerr != nil {
		return xerr
	}
	v["IPRanges"] = networkCfg.CIDR

	return nil
}

// ListInstalledFeatures returns a slice of installed features
func (c *cluster) ListInstalledFeatures(task concurrency.Task) ([]resources.Feature, fail.Error) {
	return nil, fail.NotImplementedError("ListInstalledFeatures() is not implemented yet")
}

// AddFeature installs a feature on the cluster
func (c *cluster) AddFeature(task concurrency.Task, name string, vars data.Map, settings resources.FeatureSettings) (resources.Results, fail.Error) {
	if c == nil {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	feat, xerr := NewFeature(task, name)
	if xerr != nil {
		return nil, xerr
	}
	return feat.Add(c, vars, settings)
}

// CheckFeature tells if a feature is installed on the cluster
func (c *cluster) CheckFeature(task concurrency.Task, name string, vars data.Map, settings resources.FeatureSettings) (resources.Results, fail.Error) {
	if c == nil {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	feat, xerr := NewFeature(task, name)
	if xerr != nil {
		return nil, xerr
	}

	return feat.Check(c, vars, settings)
}

// RemoveFeature uninstalls a feature from the cluster
func (c *cluster) RemoveFeature(task concurrency.Task, name string, vars data.Map, settings resources.FeatureSettings) (resources.Results, fail.Error) {
	if c == nil {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	feat, xerr := NewFeature(task, name)
	if xerr != nil {
		return nil, xerr
	}

	return feat.Remove(c, vars, settings)
}

// ExecuteScript executes the script template with the parameters on target IPAddress
func (c *cluster) ExecuteScript(task concurrency.Task, tmplName string, data map[string]interface{}, host resources.Host) (_ int, _ string, _ string, xerr fail.Error) {
	if c.IsNull() {
		return -1, "", "", fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return -1, "", "", fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if tmplName == "" {
		return -1, "", "", fail.InvalidParameterError("tmplName", "cannot be empty string")
	}
	if host.IsNull() {
		return -1, "", "", fail.InvalidParameterError("host", "cannot be null value of 'resources.Host'")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "('%s')", host.GetName()).Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	box, err := getTemplateBox()
	if err != nil {
		return 0, "", "", fail.ToError(err)
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
//		cmd = fmt.Sprintf("sudo chmod u+rx %s;sudo bash -c \"BASH_XTRACEFD=7 %s 7>/tmp/captured 2>&7\";retcode=${PIPESTATUS};cat /tmp/captured; sudo rm /tmp/captured;exit ${retcode}", path, path)
		cmd = fmt.Sprintf("sudo -- bash -c 'chmod u+rx %s; captf=$(mktemp); bash -c \"BASH_XTRACEFD=7 %s 7>$captf 2>&7\"; rc=${PIPESTATUS}; cat $captf; rm $captf; exit ${rc}'", path, path)
	} else {
//		cmd = fmt.Sprintf("sudo chmod u+rx %s;sudo bash %s;exit ${PIPESTATUS}", path, path)
		cmd = fmt.Sprintf("sudo -- bash -c 'chmod u+rx %s; bash -c %s; exit ${PIPESTATUS}'", path, path)
	}
	return host.Run(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), 2*temporal.GetLongOperationTimeout())
}

// installNodeRequirements ...
func (c *cluster) installNodeRequirements(task concurrency.Task, nodeType clusternodetype.Enum, host resources.Host, hostLabel string) (xerr fail.Error) {
	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	netCfg, xerr := c.GetNetworkConfig(task)
	if xerr != nil {
		return xerr
	}

	params := data.Map{}
	if nodeType == clusternodetype.Master {
		tp := c.service.GetTenantParameters()
		content := map[string]interface{}{
			"tenants": []map[string]interface{}{tp},
		}
		jsoned, err := json.MarshalIndent(content, "", "    ")
		if err != nil {
			return fail.ToError(err)
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
		suffix := os.Getenv("SAFESCALE_METADATA_SUFFIX")
		if suffix != "" {
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
	cfg, xerr := c.service.GetConfigurationOptions()
	if xerr == nil {
		dnsServers = cfg.GetSliceOfStrings("DNSList")
	}
	identity, xerr := c.GetIdentity(task)
	if xerr != nil {
		return xerr
	}
	params["ClusterName"] = identity.Name
	params["DNSServerIPs"] = dnsServers
	list, xerr := c.ListMasterIPs(task)
	if xerr != nil {
		return xerr
	}
	params["MasterIPs"] = list
	params["ClusterAdminUsername"] = "cladm"
	params["ClusterAdminPassword"] = identity.AdminPassword
	params["DefaultRouteIP"] = netCfg.DefaultRouteIP
	params["EndpointIP"] = netCfg.EndpointIP
	params["IPRanges"] = netCfg.CIDR
	params["SSHPublicKey"] = identity.Keypair.PublicKey
	params["SSHPrivateKey"] = identity.Keypair.PrivateKey

	if _, _, _, xerr = c.ExecuteScript(task, "node_install_requirements.sh", params, host); xerr != nil {
		return fail.Wrap(xerr, "[%s] system requirements installation failed", hostLabel)
	}

	logrus.Debugf("[%s] system requirements installation successful.", hostLabel)
	return nil
}

// Installs reverseproxy
func (c *cluster) installReverseProxy(task concurrency.Task) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	identity, xerr := c.GetIdentity(task)
	if xerr != nil {
		return xerr
	}
	clusterName := identity.Name

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	disabled := false
	xerr = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
		logrus.Debugf("[cluster %s] adding feature 'edgeproxy4network'", clusterName)
		feat, xerr := NewEmbeddedFeature(task, "edgeproxy4network")
		if xerr != nil {
			return xerr
		}
		results, xerr := feat.Add(c, data.Map{}, resources.FeatureSettings{})
		if xerr != nil {
			return xerr
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			return fail.NewError("[cluster %s] failed to add '%s': %s", clusterName, feat.GetName(), msg)
		}
		logrus.Debugf("[cluster %s] feature '%s' added successfully", clusterName, feat.GetName())
	}
	return nil
}

// installRemoteDesktop installs feature remotedesktop on all masters of the cluster
func (c *cluster) installRemoteDesktop(task concurrency.Task) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	identity, xerr := c.GetIdentity(task)
	if xerr != nil {
		return xerr
	}
	clusterName := identity.Name

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	disabled := false
	xerr = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
		logrus.Debugf("[cluster %s] adding feature 'remotedesktop'", clusterName)

		adminPassword := identity.AdminPassword

		feat, xerr := NewEmbeddedFeature(task, "remotedesktop")
		if xerr != nil {
			return xerr
		}

		// Adds remotedesktop feature on cluster (ie masters)
		vars := data.Map{
			"Username": "cladm",
			"Password": adminPassword,
		}
		r, xerr := feat.Add(c, vars, resources.FeatureSettings{})
		if xerr != nil {
			return xerr
		}

		if !r.Successful() {
			msg := r.AllErrorMessages()
			return fail.NewError("[cluster %s] failed to add 'remotedesktop' failed: %s", clusterName, msg)
		}
		logrus.Debugf("[cluster %s] feature 'remotedesktop' added successfully", clusterName)
	}
	return nil
}

// install proxycache-client feature if not disabled
func (c *cluster) installProxyCacheClient(task concurrency.Task, host resources.Host, hostLabel string) (xerr fail.Error) {
	if host.IsNull() {
		return fail.InvalidParameterError("host", "cannot be null value of 'resources.Host'")
	}
	if hostLabel == "" {
		return fail.InvalidParameterError("hostLabel", "cannot be empty string")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())
	defer fail.OnPanic(&xerr)

	disabled := false
	xerr = c.Review(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
		feat, xerr := NewEmbeddedFeature(task, "proxycache-client")
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
func (c *cluster) installProxyCacheServer(task concurrency.Task, host resources.Host, hostLabel string) (xerr fail.Error) {
	if host.IsNull() {
		return fail.InvalidParameterError("host", "cannot be null value of 'resources.Host'")
	}
	if hostLabel == "" {
		return fail.InvalidParameterError("hostLabel", "cannot be empty string")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())
	defer fail.OnPanic(&xerr)

	disabled := false
	xerr = c.Review(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
		feat, xerr := NewEmbeddedFeature(task, "proxycache-server")
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
func (c *cluster) installDocker(task concurrency.Task, host resources.Host, hostLabel string) (xerr fail.Error) {
	if host.IsNull() {
		return fail.InvalidParameterError("host", "cannot be null value of 'resources.Host'")
	}
	if hostLabel == "" {
		return fail.InvalidParameterError("hostLabel", "cannot be empty string")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	// uses NewFeature() to let a chance to the user to use it's own docker feature
	feat, xerr := NewFeature(task, "docker")
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
