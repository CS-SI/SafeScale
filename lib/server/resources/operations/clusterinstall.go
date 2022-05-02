/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/clusternodetype"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/installmethod"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/system"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
)

// TargetType returns the type of the target
//
// satisfies resources.Targetable interface
func (instance *Cluster) TargetType() featuretargettype.Enum {
	return featuretargettype.Cluster
}

// InstallMethods returns a list of installation methods usable on the target, ordered from upper to lower preference (1 = the highest preference)
// satisfies resources.Targetable interface
func (instance *Cluster) InstallMethods(context.Context) (map[uint8]installmethod.Enum, fail.Error) {
	if instance == nil || valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	out := make(map[uint8]installmethod.Enum)
	instance.localCache.RLock()
	defer instance.localCache.RUnlock()

	instance.localCache.installMethods.Range(func(k, v interface{}) bool {
		var ok bool
		out[k.(uint8)], ok = v.(installmethod.Enum)
		return ok
	})
	return out, nil
}

// InstalledFeatures returns a list of installed features
func (instance *Cluster) InstalledFeatures(context.Context) []string {
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
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		logrus.Error(xerr.Error())
		return []string{}
	}
	return out
}

// ComplementFeatureParameters configures parameters that are implicitly defined, based on target
// satisfies interface resources.Targetable
func (instance *Cluster) ComplementFeatureParameters(ctx context.Context, v data.Map) fail.Error {
	if instance == nil || valid.IsNil(instance) {
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
		config, xerr := instance.Service().GetConfigurationOptions()
		if xerr != nil {
			return xerr
		}
		if v["Username"], ok = config.Get("OperatorUsername"); !ok {
			v["Username"] = abstract.DefaultUser
		}
	}
	networkCfg, xerr := instance.GetNetworkConfig(nil)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	v["PrimaryGatewayIP"] = networkCfg.GatewayIP
	v["DefaultRouteIP"] = networkCfg.DefaultRouteIP
	v["GatewayIP"] = v["DefaultRouteIP"] // legacy ...
	v["PrimaryPublicIP"] = networkCfg.PrimaryPublicIP
	v["NetworkUsesVIP"] = networkCfg.SecondaryGatewayIP != ""
	v["SecondaryGatewayIP"] = networkCfg.SecondaryGatewayIP
	v["SecondaryPublicIP"] = networkCfg.SecondaryPublicIP
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
		master, xerr := instance.unsafeFindAvailableMaster(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		v["ClusterControlplaneEndpointIP"], xerr = master.GetPrivateIP(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		v["ClusterControlplaneUsesVIP"] = false
	}
	v["ClusterMasters"], xerr = instance.unsafeListMasters()
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

	v["ClusterMasterIPs"], xerr = instance.unsafeListMasterIPs()
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

	// VPL: already set earlier
	// v["IPRanges"] = networkCfg.CIDR
	return nil
}

// RegisterFeature registers an installed Feature in metadata of a Cluster
// satisfies interface resources.Targetable
func (instance *Cluster) RegisterFeature(ctx context.Context, feat resources.Feature, requiredBy resources.Feature, clusterContext bool) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if feat == nil {
		return fail.InvalidParameterError("feat", "cannot be null value of 'resources.Feature'")
	}

	return instance.Alter(nil, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			var item *propertiesv1.ClusterInstalledFeature
			if item, ok = featuresV1.Installed[feat.GetName()]; !ok {
				requirements, innerXErr := feat.Dependencies(ctx)
				if innerXErr != nil {
					return innerXErr
				}

				item = propertiesv1.NewClusterInstalledFeature()
				item.Name = feat.GetName()
				item.FileName = feat.GetDisplayFilename(ctx)
				item.Requires = requirements
				featuresV1.Installed[item.Name] = item
			}
			if rf, ok := requiredBy.(*Feature); ok && rf != nil && !valid.IsNil(rf) {
				item.RequiredBy[rf.GetName()] = struct{}{}
			}
			return nil
		})
	})
}

// UnregisterFeature unregisters a Feature from Cluster metadata
// satisfies interface resources.Targetable
func (instance *Cluster) UnregisterFeature(ctx context.Context, feat string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if feat == "" {
		return fail.InvalidParameterError("feat", "cannot be empty string")
	}

	return instance.Alter(nil, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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

// ListEligibleFeatures returns a slice of features eligible to Cluster
func (instance *Cluster) ListEligibleFeatures(ctx context.Context) (_ []resources.Feature, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	var emptySlice []resources.Feature
	if instance == nil || valid.IsNil(instance) {
		return emptySlice, fail.InvalidInstanceError()
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	// FIXME: 'allWithEmbedded' should be passed as parameter...
	// walk through the folders that may contain Feature files
	list, xerr := walkInsideFeatureFileFolders(allWithEmbedded)
	if xerr != nil {
		return nil, xerr
	}

	var out []resources.Feature
	for _, v := range list {
		entry, xerr := NewFeature(ctx, instance.Service(), v)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// ignore a feature file not found; weird, but fs may have changed (will be handled properly later with fswatcher)
			default:
				return nil, xerr
			}
		}

		ok, xerr := entry.Applicable(ctx, instance)
		if xerr != nil {
			return nil, xerr
		}
		if ok {
			out = append(out, entry)
		}
	}

	return out, nil
}

// ListInstalledFeatures returns a slice of installed features
func (instance *Cluster) ListInstalledFeatures(ctx context.Context) (_ []resources.Feature, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	var emptySlice []resources.Feature
	if instance == nil || valid.IsNil(instance) {
		return emptySlice, fail.InvalidInstanceError()
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	list := instance.InstalledFeatures(nil)
	// var list map[string]*propertiesv1.ClusterInstalledFeature
	// xerr := instance.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
	// 	return props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
	// 		featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
	// 		if !ok {
	// 			return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 		}
	//
	// 		list = featuresV1.Installed
	// 		return nil
	// 	})
	// })
	// xerr = debug.InjectPlannedFail(xerr)
	// if xerr != nil {
	// 	return emptySlice, xerr
	// }

	out := make([]resources.Feature, 0, len(list))
	for _, v := range list {
		item, xerr := NewFeature(ctx, instance.Service(), v)
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
	if instance == nil || valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	feat, xerr := NewFeature(ctx, instance.Service(), name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return feat.Add(ctx, instance, vars, settings)
}

// CheckFeature tells if a feature is installed on the Cluster
func (instance *Cluster) CheckFeature(ctx context.Context, name string, vars data.Map, settings resources.FeatureSettings) (resources.Results, fail.Error) {
	if instance == nil || valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	feat, xerr := NewFeature(ctx, instance.Service(), name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return feat.Check(ctx, instance, vars, settings)
}

// RemoveFeature uninstalls a feature from the Cluster
func (instance *Cluster) RemoveFeature(ctx context.Context, name string, vars data.Map, settings resources.FeatureSettings) (resources.Results, fail.Error) {
	if instance == nil || valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	feat, xerr := NewFeature(ctx, instance.Service(), name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return feat.Remove(ctx, instance, vars, settings)
}

//go:embed clusterflavors/scripts/*
var clusterFlavorScripts embed.FS

// ExecuteScript executes the script template with the parameters on target Host
func (instance *Cluster) ExecuteScript(ctx context.Context, tmplName string, variables data.Map, host resources.Host) (_ int, _ string, _ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	const invalid = -1

	if instance == nil || valid.IsNil(instance) {
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
		return invalid, "", "", xerr
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "('%s')", host.GetName()).Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage())

	timings, xerr := instance.Service().Timings()
	if xerr != nil {
		return invalid, "", "", xerr
	}

	// Configures reserved_BashLibrary template var
	bashLibraryDefinition, xerr := system.BuildBashLibraryDefinition(timings)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	bashLibraryVariables, xerr := bashLibraryDefinition.ToMap()
	if xerr != nil {
		return invalid, "", "", xerr
	}

	variables["Revision"] = system.REV

	var fisize = uint64(len(variables) + len(bashLibraryVariables))
	finalVariables := make(data.Map, fisize)
	for k, v := range variables {
		finalVariables[k] = v
	}
	for k, v := range bashLibraryVariables {
		finalVariables[k] = v
	}

	script, path, xerr := realizeTemplate("clusterflavors/scripts/"+tmplName, finalVariables, tmplName)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return invalid, "", "", fail.Wrap(xerr, "failed to realize template '%s'", tmplName)
	}

	hidesOutput := strings.Contains(script, "set +x\n")
	if hidesOutput {
		script = strings.Replace(script, "set +x\n", "\n", 1)
		script = strings.Replace(script, "exec 2>&1\n", "exec 2>&7\n", 1)
	}

	// Uploads the script into remote file
	rfcItem := Item{Remote: path}
	xerr = rfcItem.UploadString(task.Context(), script, host)
	_ = os.Remove(rfcItem.Local)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return invalid, "", "", fail.Wrap(xerr, "failed to upload %s to %s", tmplName, host.GetName())
	}

	// executes remote file
	var cmd string
	if hidesOutput {
		cmd = fmt.Sprintf("sudo -- bash -c 'sync; chmod u+rx %s; captf=$(mktemp); bash -c \"BASH_XTRACEFD=7 %s 7>$captf 2>&7\"; rc=${PIPESTATUS}; cat $captf; rm $captf; exit ${rc}'", path, path)
	} else {
		cmd = fmt.Sprintf("sudo -- bash -c 'sync; chmod u+rx %s; bash -c %s; exit ${PIPESTATUS}'", path, path)
	}

	// recover current timeout settings
	connectionTimeout := timings.ConnectionTimeout()
	executionTimeout := timings.HostLongOperationTimeout()

	// If is 126, try again 6 times, if not return the error
	rounds := 10
	for {
		rc, stdout, stderr, err := host.Run(task.Context(), cmd, outputs.COLLECT, connectionTimeout, executionTimeout)
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
			if err != nil {
				if !strings.Contains(err.Error(), "bad interpreter") {
					return rc, stdout, stderr, err
				}
			} else {
				return rc, stdout, stderr, nil
			}
		}

		rounds--
		time.Sleep(timings.SmallDelay())
	}
}

// installNodeRequirements ...
func (instance *Cluster) installNodeRequirements(ctx context.Context, nodeType clusternodetype.Enum, host resources.Host, hostLabel string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	var xerr fail.Error

	netCfg, xerr := instance.GetNetworkConfig(nil)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	timings, xerr := instance.Service().Timings()
	if xerr != nil {
		return xerr
	}

	params := data.Map{}
	if nodeType == clusternodetype.Master {
		tp, xerr := instance.Service().GetTenantParameters()
		if xerr != nil {
			return xerr
		}
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
		               probably a feature safescale-binaries to build SafeScale from source...
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

				retcode, stdout, stderr, xerr := host.Push(task, path, "/opt/safescale/bin/safescale", "root:root", "0755", temporal.ExecutionTimeout())
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
				if retcode, stdout, stderr, xerr = host.Push(task, path, "/opt/safescale/bin/safescaled", "root:root", "0755", temporal.ExecutionTimeout()); xerr != nil {
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
			retcode, stdout, stderr, xerr := host.Run(ctx, cmd, outputs.COLLECT, timings.ConnectionTimeout(), 2*timings.HostLongOperationTimeout())
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

	// FIXME: reuse ComplementFeatureParameters?
	var dnsServers []string
	cfg, xerr := instance.Service().GetConfigurationOptions()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	dnsServers = cfg.GetSliceOfStrings("DNSList")
	identity, xerr := instance.unsafeGetIdentity()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	params["ClusterName"] = identity.Name
	params["DNSServerIPs"] = dnsServers
	params["MasterIPs"], xerr = instance.unsafeListMasterIPs()
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
		return fail.Wrap(xerr, "[%s] system dependencies installation failed", hostLabel)
	}
	if retcode != 0 {
		xerr = fail.ExecutionError(nil, "failed to install common node dependencies")
		xerr.Annotate("retcode", retcode).Annotate("stdout", stdout).Annotate("stderr", stderr)
		return xerr
	}

	logrus.Debugf("[%s] system dependencies installation successful.", hostLabel)
	return nil
}

// installReverseProxy installs reverseproxy
func (instance *Cluster) installReverseProxy(ctx context.Context, params data.Map) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	identity, xerr := instance.unsafeGetIdentity()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	dockerDisabled := false
	xerr = instance.Review(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			_, dockerDisabled = featuresV1.Disabled["docker"]
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	if dockerDisabled {
		return nil
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
		feat, xerr := NewFeature(ctx, instance.Service(), "edgeproxy4subnet")
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		if params == nil {
			params = data.Map{}
		}
		results, xerr := feat.Add(ctx, instance, params, resources.FeatureSettings{})
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
func (instance *Cluster) installRemoteDesktop(ctx context.Context, params data.Map) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	identity, xerr := instance.unsafeGetIdentity()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	dockerDisabled := false
	xerr = instance.Review(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			_, dockerDisabled = featuresV1.Disabled["docker"]
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	if dockerDisabled {
		return nil
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

		feat, xerr := NewFeature(ctx, instance.Service(), "remotedesktop")
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		// Adds remotedesktop feature on Cluster (ie masters)
		if params == nil {
			params = data.Map{}
		}
		params["Username"] = "cladm"
		params["Password"] = identity.AdminPassword

		// FIXME: Bug mitigations
		params["GuacamolePort"] = 63011
		params["TomcatPort"] = 9009

		r, xerr := feat.Add(ctx, instance, params, resources.FeatureSettings{})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		if !r.Successful() {
			msg := r.AllErrorMessages()
			xerr := fail.NewError("[Cluster %s] failed to add 'remotedesktop' failed: %s", identity.Name, msg)
			_ = xerr.Annotate("ran_but_failed", true)
			return xerr
		}

		logrus.Debugf("[Cluster %s] feature 'remotedesktop' added successfully", identity.Name)
	}
	return nil
}

// installAnsible installs feature ansible on all masters of the Cluster
func (instance *Cluster) installAnsible(ctx context.Context, params data.Map) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

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

			_, disabled = featuresV1.Disabled["ansible"]
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if !disabled {
		logrus.Debugf("[Cluster %s] adding feature 'ansible'", identity.Name)

		// 1st, Feature 'ansible'
		feat, xerr := NewFeature(ctx, instance.Service(), "ansible")
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		// Adds ansible feature on Cluster (ie masters)
		if params == nil {
			params = data.Map{}
		}
		params["Username"] = "cladm"
		params["Password"] = identity.AdminPassword
		r, xerr := feat.Add(ctx, instance, params, resources.FeatureSettings{})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		if !r.Successful() {
			msg := r.AllErrorMessages()
			return fail.NewError("[Cluster %s] failed to add 'ansible': %s", identity.Name, msg)
		}
		logrus.Debugf("[Cluster %s] feature 'ansible' added successfully", identity.Name)

		// 2nd, Feature 'ansible-for-cluster' (which does the necessary for a dynamic inventory)
		feat, xerr = NewFeature(ctx, instance.Service(), "ansible-for-cluster")
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		r, xerr = feat.Add(ctx, instance, params, resources.FeatureSettings{})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		if !r.Successful() {
			msg := r.AllErrorMessages()
			return fail.NewError("[Cluster %s] failed to add 'ansible-for-cluster': %s", identity.Name, msg)
		}
		logrus.Debugf("[Cluster %s] feature 'ansible-for-cluster' added successfully", identity.Name)
	}
	return nil
}

// install proxycache-client feature if not disabled
func (instance *Cluster) installProxyCacheClient(ctx context.Context, host resources.Host, hostLabel string, params data.Map) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	var xerr fail.Error

	if host == nil {
		return fail.InvalidParameterCannotBeNilError("host")
	}
	if hostLabel == "" {
		return fail.InvalidParameterError("hostLabel", "cannot be empty string")
	}

	dockerDisabled := false
	xerr = instance.Review(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			_, dockerDisabled = featuresV1.Disabled["docker"]
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}
	if dockerDisabled {
		return nil
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
		feat, xerr := NewFeature(ctx, instance.Service(), "proxycache-client")
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		if params == nil {
			params = data.Map{}
		}
		r, xerr := feat.Add(ctx, host, params, resources.FeatureSettings{})
		xerr = debug.InjectPlannedFail(xerr)
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
func (instance *Cluster) installProxyCacheServer(ctx context.Context, host resources.Host, hostLabel string, params data.Map) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	var xerr fail.Error

	if host == nil {
		return fail.InvalidParameterCannotBeNilError("host")
	}
	if hostLabel == "" {
		return fail.InvalidParameterError("hostLabel", "cannot be empty string")
	}

	dockerDisabled := false
	xerr = instance.Review(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			_, dockerDisabled = featuresV1.Disabled["docker"]
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	if dockerDisabled {
		return nil
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
		feat, xerr := NewFeature(ctx, instance.Service(), "proxycache-server")
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		if params == nil {
			params = data.Map{}
		}
		r, xerr := feat.Add(ctx, host, params, resources.FeatureSettings{})
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
func (instance *Cluster) installDocker(ctx context.Context, host resources.Host, hostLabel string, params data.Map) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	dockerDisabled := false
	xerr := instance.Review(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			_, dockerDisabled = featuresV1.Disabled["docker"]
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	if dockerDisabled {
		return nil
	}

	// uses NewFeature() to let a chance to the user to use its own docker feature
	feat, xerr := NewFeature(ctx, instance.Service(), "docker")
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if params == nil {
		params = data.Map{}
	}
	r, xerr := feat.Add(ctx, host, params, resources.FeatureSettings{})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	reason := false
	if !r.Successful() {
		for _, k := range r.Keys() {
			rk := r.ResultsOfKey(k)
			if !rk.Successful() {
				if len(rk.ErrorMessages()) == 0 {
					logrus.Warnf("This is a false warning for %s !!: %s", k, rk.ErrorMessages())
				} else {
					reason = true
					logrus.Warnf("This failed: %s with %s", k, spew.Sdump(rk))
				}
			}
		}

		if reason {
			return fail.NewError("[%s] failed to add feature 'docker' on host '%s': %s", hostLabel, host.GetName(), r.AllErrorMessages())
		}
	}
	logrus.Debugf("[%s] feature 'docker' addition successful.", hostLabel)
	return nil
}
