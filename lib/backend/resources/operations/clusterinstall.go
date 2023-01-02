/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"expvar"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusternodetype"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/installmethod"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/system"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"
	"github.com/zserge/metric"
)

// TargetType returns the type of the target
//
// satisfies resources.Targetable interface
func (instance *Cluster) TargetType() featuretargettype.Enum {
	return featuretargettype.Cluster
}

func incrementExpVar(name string) {
	// increase counter
	ts := expvar.Get(name)
	if ts != nil {
		switch casted := ts.(type) {
		case *expvar.Int:
			casted.Add(1)
		case metric.Metric:
			casted.Add(1)
		}
	}
}

// InstallMethods returns a list of installation methods usable on the target, ordered from upper to lower preference (1 = the highest preference)
// satisfies resources.Targetable interface
func (instance *Cluster) InstallMethods(ctx context.Context) (map[uint8]installmethod.Enum, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	incrementExpVar("cluster.cache.hit")

	theFlavor, xerr := instance.unsafeGetFlavor(ctx)
	if xerr != nil {
		return nil, xerr
	}

	res := make(map[uint8]installmethod.Enum)
	res[0] = installmethod.Bash
	res[1] = installmethod.None
	if theFlavor == clusterflavor.K8S {
		res[2] = installmethod.Helm
	}

	return res, nil
}

// InstalledFeatures returns a list of installed features
func (instance *Cluster) InstalledFeatures(ctx context.Context) ([]string, fail.Error) {
	if valid.IsNull(instance) {
		return []string{}, fail.InvalidInstanceError()
	}

	var out []string
	xerr := instance.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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
		xerr = fail.Wrap(xerr, callstack.WhereIsThis())
		return []string{}, xerr
	}
	return out, nil
}

// ComplementFeatureParameters configures parameters that are implicitly defined, based on target
func (instance *Cluster) ComplementFeatureParameters(inctx context.Context, v data.Map) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	defer elapsed("ComplementFeatureParameters")()

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	defer func() {
		if ferr != nil {
			// FIXME: OPP Remove this later
			logrus.WithContext(inctx).Errorf("Unexpected error: %s", ferr)
		}
	}()

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	identity, xerr := instance.unsafeGetIdentity(ctx)
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
		config, xerr := instance.Service().GetConfigurationOptions(ctx)
		if xerr != nil {
			return xerr
		}
		if v["Username"], ok = config.Get("OperatorUsername"); !ok {
			v["Username"] = abstract.DefaultUser
		}
	}
	networkCfg, xerr := instance.GetNetworkConfig(ctx)
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
	xerr = instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
		xerr = fail.Wrap(xerr, callstack.WhereIsThis())
		return xerr
	}

	if len(instance.masterIPs) == 0 {
		mips, xerr := instance.unsafeListMasterIPs(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
		instance.masterIPs = mips
	}

	if controlPlaneV1.VirtualIP != nil && controlPlaneV1.VirtualIP.PrivateIP != "" {
		v["ClusterControlplaneUsesVIP"] = true
		v["ClusterControlplaneEndpointIP"] = controlPlaneV1.VirtualIP.PrivateIP
	} else {
		// Don't set ClusterControlplaneUsesVIP if there is no VIP... use IP of first available master instead
		for _, k := range instance.masterIPs {
			v["ClusterControlplaneEndpointIP"] = k
			v["ClusterControlplaneUsesVIP"] = false
			break
		}
	}

	if len(instance.masterIPs) > 0 {
		v["ClusterMasterIPs"] = instance.masterIPs
	} else {
		val, xerr := instance.newunsafeListMasterIPs(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
		v["ClusterMasterIPs"] = val
		instance.masterIPs = val
	}

	if len(instance.nodeIPs) > 0 {
		v["ClusterNodeIPs"] = instance.nodeIPs
	} else {
		val, xerr := instance.newunsafeListNodeIPs(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
		v["ClusterNodeIPs"] = val
		instance.nodeIPs = val
	}

	return nil
}

// RegisterFeature registers an installed Feature in metadata of a Cluster
// satisfies interface resources.Targetable
func (instance *Cluster) RegisterFeature(
	ctx context.Context, feat resources.Feature, requiredBy resources.Feature, clusterContext bool,
) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if feat == nil {
		return fail.InvalidParameterError("feat", "cannot be null value of 'resources.Feature'")
	}

	xerr := instance.Alter(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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
	if xerr != nil {
		xerr = fail.Wrap(xerr, callstack.WhereIsThis())
	}
	return xerr
}

// UnregisterFeature unregisters a Feature from Cluster metadata
// satisfies interface resources.Targetable
func (instance *Cluster) UnregisterFeature(inctx context.Context, feat string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if feat == "" {
		return fail.InvalidParameterError("feat", "cannot be empty string")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	xerr := instance.Alter(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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
	if xerr != nil {
		xerr = fail.Wrap(xerr, callstack.WhereIsThis())
	}
	return xerr
}

// ListEligibleFeatures returns a slice of features eligible to Cluster
func (instance *Cluster) ListEligibleFeatures(ctx context.Context) (_ []resources.Feature, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	// FIXME: 'allWithEmbedded' should be passed as parameter...
	// walk through the folders that may contain Feature files
	list, xerr := walkInsideFeatureFileFolders(ctx, allWithEmbedded)
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

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	list, xerr := instance.InstalledFeatures(ctx)
	if xerr != nil {
		return nil, xerr
	}

	out := make([]resources.Feature, 0, len(list))
	for _, v := range list {
		item, xerr := NewFeature(ctx, instance.Service(), v)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		out = append(out, item)
	}
	return out, nil
}

// AddFeature installs a feature on the Cluster
func (instance *Cluster) AddFeature(
	ctx context.Context, name string, vars data.Map, settings resources.FeatureSettings,
) (resources.Results, fail.Error) {
	if valid.IsNil(instance) {
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
func (instance *Cluster) CheckFeature(
	ctx context.Context, name string, vars data.Map, settings resources.FeatureSettings,
) (resources.Results, fail.Error) {
	if valid.IsNil(instance) {
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
func (instance *Cluster) RemoveFeature(
	ctx context.Context, name string, vars data.Map, settings resources.FeatureSettings,
) (resources.Results, fail.Error) {
	if valid.IsNil(instance) {
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
func (instance *Cluster) ExecuteScript(
	inctx context.Context, tmplName string, variables data.Map, host resources.Host,
) (_ int, _ string, _ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	const invalid = -1

	if valid.IsNil(instance) {
		return invalid, "", "", fail.InvalidInstanceError()
	}
	if tmplName == "" {
		return invalid, "", "", fail.InvalidParameterError("tmplName", "cannot be empty string")
	}
	if host == nil {
		return invalid, "", "", fail.InvalidParameterCannotBeNilError("host")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		a    int
		b    string
		c    string
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		timings, xerr := instance.Service().Timings()
		if xerr != nil {
			chRes <- result{invalid, "", "", xerr}
			return
		}

		// Configures reserved_BashLibrary template var
		bashLibraryDefinition, xerr := system.BuildBashLibraryDefinition(timings)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{invalid, "", "", xerr}
			return
		}

		bashLibraryVariables, xerr := bashLibraryDefinition.ToMap()
		if xerr != nil {
			chRes <- result{invalid, "", "", xerr}
			return
		}

		variables["Revision"] = system.REV

		if len(variables) > 64*1024 {
			chRes <- result{invalid, "", "", fail.OverflowError(nil, 64*1024, "variables, value too large")}
			return
		}

		if len(bashLibraryVariables) > 64*1024 {
			chRes <- result{invalid, "", "", fail.OverflowError(nil, 64*1024, "bashLibraryVariables, value too large")}
			return
		}

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
			chRes <- result{invalid, "", "", fail.Wrap(xerr, "failed to realize template '%s'", tmplName)}
			return
		}

		hidesOutput := strings.Contains(script, "set +x\n")
		if hidesOutput {
			script = strings.Replace(script, "set +x\n", "\n", 1)
			script = strings.Replace(script, "exec 2>&1\n", "exec 2>&7\n", 1)
		}

		// Uploads the script into remote file
		rfcItem := Item{Remote: path}
		xerr = rfcItem.UploadString(ctx, script, host)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{invalid, "", "", fail.Wrap(xerr, "failed to upload %s to %s", tmplName, host.GetName())}
			return
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
			rc, stdout, stderr, err := host.Run(ctx, cmd, outputs.COLLECT, connectionTimeout, executionTimeout)
			if rc == 126 {
				logrus.WithContext(ctx).Debugf("Text busy happened")
			}

			if rc != 126 || rounds == 0 {
				if rc == 126 {
					logrus.WithContext(ctx).Warnf("Text busy killed the script")
				}
				chRes <- result{rc, stdout, stderr, err}
				return
			}

			if !(strings.Contains(stdout, "bad interpreter") || strings.Contains(stderr, "bad interpreter")) {
				if err != nil {
					if !strings.Contains(err.Error(), "bad interpreter") {
						chRes <- result{rc, stdout, stderr, err}
						return
					}
				} else {
					chRes <- result{rc, stdout, stderr, nil}
					return
				}
			}

			rounds--
			time.Sleep(timings.SmallDelay())
		}
	}()
	select {
	case res := <-chRes:
		return res.a, res.b, res.c, res.rErr
	case <-ctx.Done():
		return invalid, "", "", fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return invalid, "", "", fail.ConvertError(inctx.Err())
	}
}

// installNodeRequirements ...
func (instance *Cluster) installNodeRequirements(
	inctx context.Context, nodeType clusternodetype.Enum, host resources.Host, hostLabel string, pars abstract.ClusterRequest,
) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		if oldKey := ctx.Value("ID"); oldKey != nil {
			ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/feature/install/requirements/%s", oldKey, hostLabel)) // nolint
		}

		netCfg, xerr := instance.GetNetworkConfig(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		if netCfg == nil {
			chRes <- result{fail.InconsistentError("network cfg for cluster is nil")}
			return
		}

		timings, xerr := instance.Service().Timings()
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		params := data.NewMap()
		if nodeType == clusternodetype.Master {
			tp, xerr := instance.Service().GetTenantParameters()
			if xerr != nil {
				chRes <- result{xerr}
				return
			}
			content := map[string]interface{}{
				"tenants": []map[string]interface{}{tp},
			}
			jsoned, err := json.MarshalIndent(content, "", "    ")
			err = debug.InjectPlannedError(err)
			if err != nil {
				chRes <- result{fail.ConvertError(err)}
				return
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
					chRes <- result{fail.Wrap(xerr, "failed to submit content of SAFESCALE_METADATA_SUFFIX to Host '%s'", host.GetName())}
					return
				}
				if retcode != 0 {
					output := stdout
					if output != "" && stderr != "" {
						output += "\n" + stderr
					} else if stderr != "" {
						output = stderr
					}
					msg := fmt.Sprintf("failed to copy content of SAFESCALE_METADATA_SUFFIX to Host '%s': %s", host.GetName(), output)
					chRes <- result{fail.NewError(strprocess.Capitalize(msg))}
					return
				}
			}
		}

		// FIXME: reuse ComplementFeatureParameters?
		var dnsServers []string
		cfg, xerr := instance.Service().GetConfigurationOptions(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		dnsServers = cfg.GetSliceOfStrings("DNSList")
		identity, xerr := instance.unsafeGetIdentity(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		params["ClusterName"] = identity.Name
		params["DNSServerIPs"] = dnsServers

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
			chRes <- result{fail.Wrap(xerr, "system dependencies installation failed")}
			return
		}
		if retcode != 0 {
			xerr = fail.ExecutionError(nil, "failed to install common node dependencies")
			xerr.Annotate("retcode", retcode).Annotate("stdout", stdout).Annotate("stderr", stderr)
			chRes <- result{xerr}
			return
		}

		// if docker is not disabled then is installed by default
		if _, ok := pars.DisabledDefaultFeatures["docker"]; !ok {
			retcode, stdout, stderr, xerr = instance.ExecuteScript(ctx, "node_install_docker.sh", params, host)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{fail.Wrap(xerr, "system docker installation failed")}
				return
			}
			if retcode != 0 {
				xerr = fail.ExecutionError(nil, "failed to install common docker dependencies")
				xerr.Annotate("retcode", retcode).Annotate("stdout", stdout).Annotate("stderr", stderr)
				chRes <- result{xerr}
				return
			}

			xerr = host.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(hostproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
					featuresV1, ok := clonable.(*propertiesv1.HostFeatures)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					featuresV1.Installed["docker"] = &propertiesv1.HostInstalledFeature{}
					return nil
				})
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				chRes <- result{xerr}
				return
			}
		}

		logrus.WithContext(ctx).Debugf("system dependencies installation successful.")
		chRes <- result{nil}

	}()
	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return fail.ConvertError(inctx.Err())
	}

}

// installReverseProxy installs reverseproxy
func (instance *Cluster) installReverseProxy(inctx context.Context, params data.Map, req abstract.ClusterRequest) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		if oldKey := ctx.Value("ID"); oldKey != nil {
			ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/feature/install/reverseproxy/%s", oldKey, instance.GetName())) // nolint
		}

		identity, xerr := instance.unsafeGetIdentity(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		disabled := false
		if _, ok := req.DisabledDefaultFeatures["docker"]; ok {
			disabled = true
		}

		if _, ok := req.DisabledDefaultFeatures["reverseproxy"]; ok {
			disabled = true
		}

		clusterName := identity.Name

		if !disabled {
			logrus.WithContext(ctx).Debugf("[Cluster %s] adding feature 'edgeproxy4subnet'", clusterName)
			feat, xerr := NewFeature(ctx, instance.Service(), "edgeproxy4subnet")
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			params, _ := data.FromMap(params)
			results, xerr := feat.Add(ctx, instance, params, resources.FeatureSettings{})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			if !results.Successful() {
				msg := results.AllErrorMessages()
				chRes <- result{fail.NewError("[Cluster %s] failed to add '%s': %s", clusterName, feat.GetName(), msg)}
				return
			}

			xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
					featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					featuresV1.Installed[feat.GetName()] = &propertiesv1.ClusterInstalledFeature{
						Name: feat.GetName(),
					}
					return nil
				})
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				chRes <- result{xerr}
				return
			}

			logrus.WithContext(ctx).Debugf("[Cluster %s] feature '%s' added successfully", clusterName, feat.GetName())
			chRes <- result{nil}
			return
		}

		logrus.WithContext(ctx).Infof("[Cluster %s] reverseproxy (feature 'edgeproxy4subnet' not installed because disabled", clusterName)
		chRes <- result{nil}
	}()
	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return fail.ConvertError(inctx.Err())
	}
}

// installRemoteDesktop installs feature remotedesktop on all masters of the Cluster
func (instance *Cluster) installRemoteDesktop(inctx context.Context, params data.Map, req abstract.ClusterRequest) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		if oldKey := ctx.Value("ID"); oldKey != nil {
			ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/feature/install/remotedesktop/%s", oldKey, instance.GetName())) // nolint
		}

		identity, xerr := instance.unsafeGetIdentity(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		disabled := false
		if _, ok := req.DisabledDefaultFeatures["docker"]; ok {
			disabled = true
		}

		if _, ok := req.DisabledDefaultFeatures["remotedesktop"]; ok {
			disabled = true
		}

		if !disabled {
			logrus.WithContext(ctx).Debugf("[Cluster %s] adding feature 'remotedesktop'", identity.Name)

			feat, xerr := NewFeature(ctx, instance.Service(), "remotedesktop")
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			// Adds remotedesktop feature on Cluster (ie masters)
			params, _ := data.FromMap(params)
			params["Username"] = "cladm"
			params["Password"] = identity.AdminPassword

			// FIXME: Bug mitigations
			params["GuacamolePort"] = 63011
			params["TomcatPort"] = 9009

			r, xerr := feat.Add(ctx, instance, params, resources.FeatureSettings{})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			if !r.Successful() {
				msg := r.AllErrorMessages()
				xerr := fail.NewError("[Cluster %s] failed to add 'remotedesktop' failed: %s", identity.Name, msg)
				_ = xerr.Annotate("ran_but_failed", true)
				chRes <- result{xerr}
				return
			}

			xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
					featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					featuresV1.Installed["remotedesktop"] = &propertiesv1.ClusterInstalledFeature{
						Name: "remotedesktop",
					}
					return nil
				})
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				chRes <- result{xerr}
				return
			}

			logrus.WithContext(ctx).Debugf("[Cluster %s] feature 'remotedesktop' added successfully", identity.Name)
		}

		chRes <- result{nil}

	}()
	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return fail.ConvertError(inctx.Err())
	}
}

// installAnsible installs feature ansible on all masters of the Cluster
func (instance *Cluster) installAnsible(inctx context.Context, params data.Map) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		if oldKey := ctx.Value("ID"); oldKey != nil {
			ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/feature/install/ansible/%s", oldKey, instance.GetName())) // nolint
		}

		identity, xerr := instance.unsafeGetIdentity(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		disabled := false
		xerr = instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
			xerr = fail.Wrap(xerr, callstack.WhereIsThis())
			chRes <- result{xerr}
			return
		}

		if !disabled {
			logrus.WithContext(ctx).Debugf("[Cluster %s] adding feature 'ansible'", identity.Name)

			// 1st, Feature 'ansible'
			feat, xerr := NewFeature(ctx, instance.Service(), "ansible")
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			// Adds ansible feature on Cluster (ie masters)
			params, _ := data.FromMap(params)
			params["Username"] = "cladm"
			params["Password"] = identity.AdminPassword
			r, xerr := feat.Add(ctx, instance, params, resources.FeatureSettings{})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			if !r.Successful() {
				msg := r.AllErrorMessages()
				chRes <- result{fail.NewError("[Cluster %s] failed to add 'ansible': %s", identity.Name, msg)}
				return
			}
			logrus.WithContext(ctx).Debugf("[Cluster %s] feature 'ansible' added successfully", identity.Name)

			// 2nd, Feature 'ansible-for-cluster' (which does the necessary for a dynamic inventory)
			feat, xerr = NewFeature(ctx, instance.Service(), "ansible-for-cluster")
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			r, xerr = feat.Add(ctx, instance, params, resources.FeatureSettings{})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			if !r.Successful() {
				msg := r.AllErrorMessages()
				chRes <- result{fail.NewError("[Cluster %s] failed to add 'ansible-for-cluster': %s", identity.Name, msg)}
				return
			}

			xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
					featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					featuresV1.Installed["ansible-for-cluster"] = &propertiesv1.ClusterInstalledFeature{
						Name: "ansible-for-cluster",
					}
					return nil
				})
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				chRes <- result{xerr}
				return
			}

			logrus.WithContext(ctx).Debugf("[Cluster %s] feature 'ansible-for-cluster' added successfully", identity.Name)
		}
		chRes <- result{nil}

	}()
	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return fail.ConvertError(inctx.Err())
	}
}

// installDocker installs docker and docker-compose
func (instance *Cluster) installDocker(
	inctx context.Context, host resources.Host, hostLabel string, params data.Map, pars abstract.ClusterRequest,
) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		if oldKey := ctx.Value("ID"); oldKey != nil {
			ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/feature/install/docker/%s", oldKey, hostLabel)) // nolint
		}

		if _, ok := pars.DisabledDefaultFeatures["docker"]; ok {
			chRes <- result{nil}
			return
		}

		// uses NewFeature() to let a chance to the user to use its own docker feature
		feat, xerr := NewFeature(ctx, instance.Service(), "docker")
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		params, _ := data.FromMap(params)
		r, xerr := feat.Add(ctx, host, params, resources.FeatureSettings{})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		reason := false
		if !r.Successful() {
			for _, k := range r.Keys() {
				rk := r.ResultsOfKey(k)
				if !rk.Successful() {
					if len(rk.ErrorMessages()) == 0 {
						logrus.WithContext(ctx).Warnf("This is a false warning for %s !!: %s", k, rk.ErrorMessages())
					} else {
						reason = true
						logrus.WithContext(ctx).Warnf("This failed: %s with %s", k, spew.Sdump(rk))
					}
				}
			}

			if reason {
				chRes <- result{fail.NewError("[%s] failed to add feature 'docker' on host '%s': %s", hostLabel, host.GetName(), r.AllErrorMessages())}
				return
			}
		}

		xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Alter(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
				featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				featuresV1.Installed[feat.GetName()] = &propertiesv1.ClusterInstalledFeature{
					Name: feat.GetName(),
				}
				return nil
			})
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			xerr = fail.Wrap(xerr, callstack.WhereIsThis())
			chRes <- result{xerr}
			return
		}

		logrus.WithContext(ctx).Debugf("[%s] feature 'docker' addition successful.", hostLabel)
		chRes <- result{nil}
	}()
	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return fail.ConvertError(inctx.Err())
	}
}
