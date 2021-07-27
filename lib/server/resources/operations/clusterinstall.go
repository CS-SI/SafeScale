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
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	rice "github.com/GeertJohan/go.rice"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
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
		err = debug.InjectPlannedError(err)
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
func (instance *Cluster) TargetType() featuretargettype.Enum {
	return featuretargettype.Cluster
}

// InstallMethods returns a list of installation methods useable on the target, ordered from upper to lower preference (1 = the highest preference)
// satisfies resources.Targetable interface
func (instance *Cluster) InstallMethods() map[uint8]installmethod.Enum {
	if instance == nil || instance.IsNull() {
		logrus.Error(fail.InvalidInstanceError().Error())
		return nil
	}

	out := make(map[uint8]installmethod.Enum)
	instance.installMethods.Range(func(k, v interface{}) bool {
		out[k.(uint8)] = v.(installmethod.Enum)
		return true
	})
	return out
}

// InstalledFeatures returns a list of installed features
func (instance *Cluster) InstalledFeatures() []string {
	if instance == nil {
		return []string{}
	}

	var out []string
	xerr := instance.Review(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			for k := range featuresV1.Installed {
				out = append(out, k)
			}
			return nil
		})
	})
	if xerr != nil {
		logrus.Error(xerr.Error())
		return []string{}
	}
	return out
}

// ComplementFeatureParameters FIXME: include the Cluster part of setImplicitParameters() from feature
// ComplementFeatureParameters configures parameters that are implicitly defined, based on target
// satisfies interface resources.Targetable
func (instance *Cluster) ComplementFeatureParameters(ctx context.Context, v data.Map) fail.Error {
	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}

	identity, xerr := instance.unsafeGetIdentity()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	v["ClusterComplexity"] = strings.ToLower(identity.Complexity.String())
	v["ClusterFlavor"] = strings.ToLower(identity.Flavor.String())
	v["ClusterName"] = identity.Name
	v["ClusterAdminUsername"] = "cladm"
	v["ClusterAdminPassword"] = identity.AdminPassword
	if _, ok := v["Username"]; !ok {
		v["Username"] = abstract.DefaultUser
	}
	networkCfg, xerr := instance.GetNetworkConfig()
	xerr = debug.InjectPlannedFail(xerr)
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
	xerr = instance.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.ControlPlaneV1, func(clonable data.Clonable) fail.Error {
			var ok bool
			controlPlaneV1, ok = clonable.(*propertiesv1.ClusterControlplane)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterControlplane' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if controlPlaneV1.VirtualIP != nil && controlPlaneV1.VirtualIP.PrivateIP != "" {
		v["ClusterControlplaneUsesVIP"] = true
		v["ClusterControlplaneEndpointIP"] = controlPlaneV1.VirtualIP.PrivateIP
	} else {
		// Don't set ClusterControlplaneUsesVIP if there is no VIP... use IP of first available master instead
		master, xerr := instance.UnsafeFindAvailableMaster(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		v["ClusterControlplaneEndpointIP"], xerr = master.GetPrivateIP()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		v["ClusterControlplaneUsesVIP"] = false
	}
	v["ClusterMasters"], xerr = instance.UnsafeListMasters()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	list := make([]string, 0, len(v["ClusterMasters"].(resources.IndexedListOfClusterNodes)))
	for _, v := range v["ClusterMasters"].(resources.IndexedListOfClusterNodes) {
		list = append(list, v.Name)
	}
	v["ClusterMasterNames"] = list

	list = make([]string, 0, len(v["ClusterMasters"].(resources.IndexedListOfClusterNodes)))
	for _, v := range v["ClusterMasters"].(resources.IndexedListOfClusterNodes) {
		list = append(list, v.ID)
	}
	v["ClusterMasterIDs"] = list

	v["ClusterMasterIPs"], xerr = instance.UnsafeListMasterIPs()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	v["ClusterNodes"], xerr = instance.unsafeListNodes()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	list = make([]string, 0, len(v["ClusterNodes"].(resources.IndexedListOfClusterNodes)))
	for _, v := range v["ClusterNodes"].(resources.IndexedListOfClusterNodes) {
		list = append(list, v.Name)
	}
	v["ClusterNodeNames"] = list

	list = make([]string, 0, len(v["ClusterNodes"].(resources.IndexedListOfClusterNodes)))
	for _, v := range v["ClusterNodes"].(resources.IndexedListOfClusterNodes) {
		list = append(list, v.ID)
	}
	v["ClusterNodeIDs"] = list

	v["ClusterNodeIPs"], xerr = instance.unsafeListNodeIPs()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	v["IPRanges"] = networkCfg.CIDR
	return nil
}

// RegisterFeature registers an installed Feature in metadata of a Cluster
// satisfies interface resources.Targetable
func (instance *Cluster) RegisterFeature(feat resources.Feature, requiredBy resources.Feature, _ bool) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if feat == nil {
		return fail.InvalidParameterError("feat", "cannot be null value of 'resources.Feature'")
	}

	return instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
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
				item.Name = feat.GetName()
				item.FileName = feat.GetDisplayFilename()
				item.Requires = requirements
				featuresV1.Installed[item.Name] = item
			}
			if rf, ok := requiredBy.(*Feature); ok && rf != nil && !rf.IsNull() {
				item.RequiredBy[rf.GetName()] = struct{}{}
			}
			return nil
		})
	})
}

// UnregisterFeature unregisters a Feature from Cluster metadata
// satisfies interface resources.Targetable
func (instance *Cluster) UnregisterFeature(feat string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if feat == "" {
		return fail.InvalidParameterError("feat", "cannot be empty string")
	}

	return instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
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
func (instance *Cluster) ListInstalledFeatures(ctx context.Context) (_ []resources.Feature, xerr fail.Error) {
	var emptySlice []resources.Feature
	if instance == nil || instance.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	var list map[string]*propertiesv1.ClusterInstalledFeature
	xerr = instance.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			list = featuresV1.Installed
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return emptySlice, xerr
	}

	out := make([]resources.Feature, 0, len(list))
	for k := range list {
		item, xerr := NewFeature(instance.GetService(), k)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return emptySlice, xerr
		}

		out = append(out, item)
	}
	return out, nil
}

// AddFeature installs a feature on the Cluster
func (instance *Cluster) AddFeature(ctx context.Context, name string, vars data.Map, settings resources.FeatureSettings) (resources.Results, fail.Error) {
	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	feat, xerr := NewFeature(instance.GetService(), name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return feat.Add(ctx, instance, vars, settings)
}

// CheckFeature tells if a feature is installed on the Cluster
func (instance *Cluster) CheckFeature(ctx context.Context, name string, vars data.Map, settings resources.FeatureSettings) (resources.Results, fail.Error) {
	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	feat, xerr := NewFeature(instance.GetService(), name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return feat.Check(ctx, instance, vars, settings)
}

// RemoveFeature uninstalls a feature from the Cluster
func (instance *Cluster) RemoveFeature(ctx context.Context, name string, vars data.Map, settings resources.FeatureSettings) (resources.Results, fail.Error) {
	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	feat, xerr := NewFeature(instance.GetService(), name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return feat.Remove(ctx, instance, vars, settings)
}

// ExecuteScript executes the script template with the parameters on target Host
func (instance *Cluster) ExecuteScript(ctx context.Context, tmplName string, data map[string]interface{}, host resources.Host) (_ int, _ string, _ string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)
	const invalid = -1

	if instance == nil || instance.IsNull() {
		return invalid, "", "", fail.InvalidInstanceError()
	}
	if tmplName == "" {
		return invalid, "", "", fail.InvalidParameterError("tmplName", "cannot be empty string")
	}
	if host == nil {
		return invalid, "", "", fail.InvalidParameterCannotBeNilError("host")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return invalid, "", "", xerr
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "('%s')", host.GetName()).Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	box, err := getTemplateBox()
	err = debug.InjectPlannedError(err)
	if err != nil {
		return invalid, "", "", fail.ConvertError(err)
	}

	// Configures reserved_BashLibrary template var
	bashLibrary, xerr := system.GetBashLibrary()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return invalid, "", "", xerr
	}
	data["reserved_BashLibrary"] = bashLibrary

	// Sets delays and timeouts for script
	data["reserved_DefaultDelay"] = uint(math.Ceil(2 * temporal.GetDefaultDelay().Seconds()))
	data["reserved_DefaultTimeout"] = strings.Replace(
		(temporal.GetHostTimeout() / 2).Truncate(time.Minute).String(), "0s", "", -1,
	)
	data["reserved_LongTimeout"] = strings.Replace(
		temporal.GetLongOperationTimeout().Truncate(time.Minute).String(), "0s", "", -1,
	)
	data["reserved_ClusterJoinTimeout"] = strings.Replace(
		temporal.GetLongOperationTimeout().Truncate(time.Minute).String(), "0s", "", -1,
	)
	data["reserved_DockerImagePullTimeout"] = strings.Replace(
		(2 * temporal.GetHostTimeout()).Truncate(time.Minute).String(), "0s", "", -1,
	)

	script, path, xerr := realizeTemplate(box, tmplName, data, tmplName)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return invalid, "", "", fail.Wrap(xerr, "failed to realize template '%s'", tmplName)
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
	xerr = rfcItem.UploadString(task.Context(), script, host)
	_ = os.Remove(rfcItem.Local)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	// executes remote file
	var cmd string
	if hidesOutput {
		cmd = fmt.Sprintf("sudo -- bash -c 'sync; chmod u+rx %s; captf=$(mktemp); bash -c \"BASH_XTRACEFD=7 %s 7>$captf 2>&7\"; rc=${PIPESTATUS}; cat $captf; rm $captf; exit ${rc}'", path, path)
	} else {
		cmd = fmt.Sprintf("sudo -- bash -c 'sync; chmod u+rx %s; bash -c %s; exit ${PIPESTATUS}'", path, path)
	}

	// If is 126, try again 6 times, if not return the error
	rounds := 10
	for {
		rc, stdout, stderr, err := host.Run(ctx, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), 2*temporal.GetLongOperationTimeout())
		if rc == 126 {
			logrus.Debugf("Text busy happened")
		}

		if rc != 126 || rounds == 0 {
			if rc == 126 {
				logrus.Warnf("Text busy killed the script")
			}
			return rc, stdout, stderr, err
		}

		if !(strings.Contains(stdout, "bad interpreter") || strings.Contains(stderr, "bad interpreter")) {
			if err == nil {
				return rc, stdout, stderr, err
			}

			if !strings.Contains(err.Error(), "bad interpreter") {
				return rc, stdout, stderr, err
			}
		}

		rounds = rounds - 1
		time.Sleep(temporal.GetMinDelay())
	}
}

// installNodeRequirements ...
func (instance *Cluster) installNodeRequirements(ctx context.Context, nodeType clusternodetype.Enum, host resources.Host, hostLabel string) (xerr fail.Error) {
	netCfg, xerr := instance.GetNetworkConfig()
	xerr = debug.InjectPlannedFail(xerr)
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
		err = debug.InjectPlannedError(err)
		if err != nil {
			return fail.ConvertError(err)
		}
		params["reserved_TenantJSON"] = string(jsoned)

		// Finds the MetadataFolder where the current binary resides
		var (
			binaryDir string
			path      string
		)
		exe, _ := os.Executable()
		if exe != "" {
			binaryDir = filepath.Dir(exe)
		}

		_, _ = binaryDir, path
		/* FIXME: VPL: disable binaries upload until proper solution (does not work with different architectures between client and remote),
				               probaly a feature safescale-binaries to build SafeScale from source...
				// Uploads safescale binary
				if binaryDir != "" {
					path = binaryDir + "/safescale"
				}
				if path == "" {
					path, err = exec.LookPath("safescale")
					err = debug.InjectPlannedError((err)
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
					err = debug.InjectPlannedError((err)
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
		*/
		// Optionally propagate SAFESCALE_METADATA_SUFFIX env vars to master
		if suffix := os.Getenv("SAFESCALE_METADATA_SUFFIX"); suffix != "" {
			cmdTmpl := "sudo sed -i '/^SAFESCALE_METADATA_SUFFIX=/{h;s/=.*/=%s/};${x;/^$/{s//SAFESCALE_METADATA_SUFFIX=%s/;H};x}' /etc/environment"
			cmd := fmt.Sprintf(cmdTmpl, suffix, suffix)
			retcode, stdout, stderr, xerr := host.Run(ctx, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), 2*temporal.GetLongOperationTimeout())
			xerr = debug.InjectPlannedFail(xerr)
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
	xerr = debug.InjectPlannedFail(xerr)
	if xerr == nil {
		dnsServers = cfg.GetSliceOfStrings("DNSList")
	}
	identity, xerr := instance.unsafeGetIdentity()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	params["ClusterName"] = identity.Name
	params["DNSServerIPs"] = dnsServers
	params["MasterIPs"], xerr = instance.UnsafeListMasterIPs()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	params["ClusterAdminUsername"] = "cladm"
	params["ClusterAdminPassword"] = identity.AdminPassword
	params["DefaultRouteIP"] = netCfg.DefaultRouteIP
	params["EndpointIP"] = netCfg.EndpointIP
	params["IPRanges"] = netCfg.CIDR
	params["SSHPublicKey"] = identity.Keypair.PublicKey
	params["SSHPrivateKey"] = identity.Keypair.PrivateKey

	retcode, stdout, stderr, xerr := instance.ExecuteScript(ctx, "node_install_requirements.sh", params, host)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "[%s] system requirements installation failed", hostLabel)
	}
	if retcode != 0 {
		xerr = fail.ExecutionError(nil, "failed to install common node requirements")
		_ = xerr.Annotate("retcode", retcode).Annotate("stdout", stdout).Annotate("stderr", stderr)
		return xerr
	}

	logrus.Debugf("[%s] system requirements installation successful.", hostLabel)
	return nil
}

// Installs reverseproxy
func (instance *Cluster) installReverseProxy(ctx context.Context) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	identity, xerr := instance.unsafeGetIdentity()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	clusterName := identity.Name
	disabled := false
	xerr = instance.Review(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			_, disabled = featuresV1.Disabled["reverseproxy"]
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if !disabled {
		logrus.Debugf("[Cluster %s] adding feature 'edgeproxy4subnet'", clusterName)
		feat, xerr := NewFeature(instance.GetService(), "edgeproxy4subnet")
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		results, xerr := feat.Add(ctx, instance, data.Map{}, resources.FeatureSettings{})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		if !results.Successful() {
			msg := results.AllErrorMessages()
			return fail.NewError("[Cluster %s] failed to add '%s': %s", clusterName, feat.GetName(), msg)
		}
		logrus.Debugf("[Cluster %s] feature '%s' added successfully", clusterName, feat.GetName())
		return nil
	}

	logrus.Infof("[Cluster %s] reverseproxy (feature 'edgeproxy4subnet' not installed because disabled", clusterName)
	return nil
}

// installRemoteDesktop installs feature remotedesktop on all masters of the Cluster
func (instance *Cluster) installRemoteDesktop(ctx context.Context) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	identity, xerr := instance.unsafeGetIdentity()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	disabled := false
	xerr = instance.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			_, disabled = featuresV1.Disabled["remotedesktop"]
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if !disabled {
		logrus.Debugf("[Cluster %s] adding feature 'remotedesktop'", identity.Name)

		feat, xerr := NewFeature(instance.GetService(), "remotedesktop")
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		// Adds remotedesktop feature on Cluster (ie masters)
		vars := data.Map{
			"Username": "cladm",
			"Password": identity.AdminPassword,
		}
		r, xerr := feat.Add(ctx, instance, vars, resources.FeatureSettings{})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		if !r.Successful() {
			msg := r.AllErrorMessages()
			return fail.NewError("[Cluster %s] failed to add 'remotedesktop' failed: %s", identity.Name, msg)
		}
		logrus.Debugf("[Cluster %s] feature 'remotedesktop' added successfully", identity.Name)
	}
	return nil
}

// install proxycache-client feature if not disabled
func (instance *Cluster) installProxyCacheClient(ctx context.Context, host resources.Host, hostLabel string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if host == nil {
		return fail.InvalidParameterCannotBeNilError("host")
	}
	if hostLabel == "" {
		return fail.InvalidParameterError("hostLabel", "cannot be empty string")
	}

	disabled := false
	xerr = instance.Review(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			_, disabled = featuresV1.Disabled["proxycache"]
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	if !disabled {
		feat, xerr := NewFeature(instance.GetService(), "proxycache-client")
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		r, xerr := feat.Add(ctx, host, data.Map{}, resources.FeatureSettings{})
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
func (instance *Cluster) installProxyCacheServer(ctx context.Context, host resources.Host, hostLabel string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if host == nil {
		return fail.InvalidParameterCannotBeNilError("host")
	}
	if hostLabel == "" {
		return fail.InvalidParameterError("hostLabel", "cannot be empty string")
	}

	disabled := false
	xerr = instance.Review(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			_, disabled = featuresV1.Disabled["proxycache"]
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if !disabled {
		feat, xerr := NewFeature(instance.GetService(), "proxycache-server")
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		r, xerr := feat.Add(ctx, host, data.Map{}, resources.FeatureSettings{})
		xerr = debug.InjectPlannedFail(xerr)
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

// installDocker installs docker and docker-compose
func (instance *Cluster) installDocker(ctx context.Context, host resources.Host, hostLabel string) (xerr fail.Error) {
	// uses NewFeature() to let a chance to the user to use its own docker feature
	feat, xerr := NewFeature(instance.GetService(), "docker")
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	r, xerr := feat.Add(ctx, host, data.Map{}, resources.FeatureSettings{})
	xerr = debug.InjectPlannedFail(xerr)
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
