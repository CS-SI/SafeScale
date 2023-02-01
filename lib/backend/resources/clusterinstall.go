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

package resources

import (
	"context"
	"embed"
	"expvar"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	rscapi "github.com/CS-SI/SafeScale/v22/lib/backend/resources/api"
	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"
	"github.com/zserge/metric"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusternodetype"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/system"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
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
func (instance *Cluster) InstallMethods(_ context.Context) (map[uint8]installmethod.Enum, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	out := make(map[uint8]installmethod.Enum)

	incrementExpVar("cluster.cache.hit")
	instance.localCache.installMethods.Range(func(k, v interface{}) bool {
		var ok bool
		out[k.(uint8)], ok = v.(installmethod.Enum)
		return ok
	})
	return out, nil
}

// InstalledFeatures returns a list of installed features
func (instance *Cluster) InstalledFeatures(ctx context.Context) (_ []string, ferr fail.Error) {
	if valid.IsNull(instance) {
		return []string{}, fail.InvalidInstanceError()
	}

	trx, xerr := metadata.NewTransaction[*abstract.Cluster, *Cluster](ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	var out []string
	xerr = inspectClusterMetadataProperty(ctx, trx, clusterproperty.FeaturesV1, func(p clonable.Clonable) fail.Error {
		featuresV1, innerErr := clonable.Cast[*propertiesv1.ClusterFeatures](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		for k := range featuresV1.Installed {
			out = append(out, k)
		}
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return []string{}, xerr
	}
	return out, nil
}

// ComplementFeatureParameters configures parameters that are implicitly defined, based on target
// satisfies interface resources.Targetable
func (instance *Cluster) ComplementFeatureParameters(inctx context.Context, v data.Map[string, any]) (ferr fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	trx, xerr := metadata.NewTransaction[*abstract.Cluster, *Cluster](ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	identity, xerr := trxGetIdentity(ctx, trx)
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
		config, xerr := instance.Service().ConfigurationOptions()
		if xerr != nil {
			return xerr
		}
		v["Username"] = config.OperatorUsername
		if v["username"] == "" {
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

	var cpV1 *propertiesv1.ClusterControlplane
	xerr = inspectClusterMetadataProperty(ctx, trx, clusterproperty.ControlPlaneV1, func(controlPlaneV1 *propertiesv1.ClusterControlplane) fail.Error {
		cpV1 = controlPlaneV1
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if cpV1.VirtualIP != nil && cpV1.VirtualIP.PrivateIP != "" {
		v["ClusterControlplaneUsesVIP"] = true
		v["ClusterControlplaneEndpointIP"] = cpV1.VirtualIP.PrivateIP
	} else {
		// Don't set ClusterControlplaneUsesVIP if there is no VIP... use IP of first available master instead
		master, xerr := instance.trxFindAvailableMaster(ctx, trx)
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
	v["ClusterMasters"], xerr = trxListMasters(ctx, trx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	list := make([]string, 0, len(v["ClusterMasters"].(rscapi.IndexedListOfClusterNodes)))
	for _, v := range v["ClusterMasters"].(rscapi.IndexedListOfClusterNodes) {
		list = append(list, v.Name)
	}
	v["ClusterMasterNames"] = list

	list = make([]string, 0, len(v["ClusterMasters"].(rscapi.IndexedListOfClusterNodes)))
	for _, v := range v["ClusterMasters"].(rscapi.IndexedListOfClusterNodes) {
		list = append(list, v.ID)
	}
	v["ClusterMasterIDs"] = list

	v["ClusterMasterIPs"], xerr = instance.trxListMasterIPs(ctx, trx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	v["ClusterNodes"], xerr = instance.trxListNodes(ctx, trx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	list = make([]string, 0, len(v["ClusterNodes"].(rscapi.IndexedListOfClusterNodes)))
	for _, v := range v["ClusterNodes"].(rscapi.IndexedListOfClusterNodes) {
		list = append(list, v.Name)
	}
	v["ClusterNodeNames"] = list

	list = make([]string, 0, len(v["ClusterNodes"].(rscapi.IndexedListOfClusterNodes)))
	for _, v := range v["ClusterNodes"].(rscapi.IndexedListOfClusterNodes) {
		list = append(list, v.ID)
	}
	v["ClusterNodeIDs"] = list

	v["ClusterNodeIPs"], xerr = instance.trxListNodeIPs(ctx, trx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// RegisterFeature registers an installed Feature in metadata of a Cluster
// satisfies interface resources.Targetable
func (instance *Cluster) RegisterFeature(ctx context.Context, feat *Feature, requiredBy *Feature, clusterContext bool) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if feat == nil {
		return fail.InvalidParameterError("feat", "cannot be null value of '*Feature'")
	}

	trx, xerr := newClusterTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	return alterClusterMetadataProperty(ctx, trx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
		item, ok := featuresV1.Installed[feat.GetName()]
		if !ok {
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
		if !valid.IsNil(requiredBy) {
			item.RequiredBy[requiredBy.GetName()] = struct{}{}
		}
		return nil
	})
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

	trx, xerr := metadata.NewTransaction[*abstract.Cluster, *Cluster](ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	xerr = alterClusterMetadataProperty(ctx, trx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
		delete(featuresV1.Installed, feat)
		for _, v := range featuresV1.Installed {
			delete(v.RequiredBy, feat)
		}
		return nil
	})
	if xerr != nil {
		xerr = fail.Wrap(xerr, callstack.WhereIsThis())
	}
	return xerr
}

// ListEligibleFeatures returns a slice of features eligible to Cluster
func (instance *Cluster) ListEligibleFeatures(ctx context.Context) (_ []*Feature, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	var emptySlice []*Feature
	if valid.IsNil(instance) {
		return emptySlice, fail.InvalidInstanceError()
	}

	// FIXME: 'allWithEmbedded' should be passed as parameter...
	// walk through the folders that may contain Feature files
	list, xerr := walkInsideFeatureFileFolders(ctx, allWithEmbedded)
	if xerr != nil {
		return nil, xerr
	}

	var out []*Feature
	for _, v := range list {
		entry, xerr := NewFeature(ctx, v)
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
func (instance *Cluster) ListInstalledFeatures(ctx context.Context) (_ []*Feature, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	list, xerr := instance.InstalledFeatures(ctx)
	if xerr != nil {
		return nil, xerr
	}

	out := make([]*Feature, 0, len(list))
	for _, v := range list {
		item, xerr := NewFeature(ctx, v)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		out = append(out, item)
	}
	return out, nil
}

// AddFeature installs a feature on the Cluster
func (instance *Cluster) AddFeature(ctx context.Context, name string, vars data.Map[string, any], opts ...options.Option) (rscapi.Results, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	feat, xerr := NewFeature(ctx, name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return feat.Add(ctx, instance, vars, opts...)
}

// CheckFeature tells if a feature is installed on the Cluster
func (instance *Cluster) CheckFeature(ctx context.Context, name string, vars data.Map[string, any], opts ...options.Option) (rscapi.Results, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	feat, xerr := NewFeature(ctx, name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return feat.Check(ctx, instance, vars, opts...)
}

// RemoveFeature uninstalls a feature from the Cluster
func (instance *Cluster) RemoveFeature(ctx context.Context, name string, vars data.Map[string, any], opts ...options.Option) (rscapi.Results, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	feat, xerr := NewFeature(ctx, name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return feat.Remove(ctx, instance, vars, opts...)
}

//go:embed internal/clusterflavors/scripts/*
var clusterFlavorScripts embed.FS

// ExecuteScript executes the script template with the parameters on target Host
func (instance *Cluster) ExecuteScript(inctx context.Context, tmplName string, variables data.Map[string, any], host *Host) (_ int, _ string, _ string, ferr fail.Error) {
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
		finalVariables := make(data.Map[string, any], fisize)
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
		return invalid, "", "", fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return invalid, "", "", fail.Wrap(inctx.Err())
	}
}

// trxInstallNodeRequirements ...
func (instance *Cluster) trxInstallNodeRequirements(inctx context.Context, clusterTrx clusterTransaction, nodeType clusternodetype.Enum, host *Host, hostLabel string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

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

		params := data.NewMap[string, any]()
		if nodeType == clusternodetype.Master {
			tp, xerr := instance.Service().TenantParameters()
			if xerr != nil {
				chRes <- result{xerr}
				return
			}
			content := map[string]any{
				"tenants": []map[string]any{tp},
			}
			jsoned, err := json.MarshalIndent(content, "", "    ")
			err = debug.InjectPlannedError(err)
			if err != nil {
				chRes <- result{fail.Wrap(err)}
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
		cfg, xerr := instance.Service().ConfigurationOptions()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		dnsServers = cfg.DNSServers
		identity, xerr := trxGetIdentity(ctx, clusterTrx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		params["ClusterName"] = identity.Name
		params["DNSServerIPs"] = dnsServers
		params["MasterIPs"], xerr = instance.trxListMasterIPs(ctx, clusterTrx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
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
			chRes <- result{fail.Wrap(xerr, "[%s] system dependencies installation failed", hostLabel)}
			return
		}
		if retcode != 0 {
			xerr = fail.ExecutionError(nil, "failed to install common node dependencies")
			xerr.Annotate("retcode", retcode).Annotate("stdout", stdout).Annotate("stderr", stderr)
			chRes <- result{xerr}
			return
		}

		logrus.WithContext(ctx).Debugf("[%s] system dependencies installation successful.", hostLabel)
		chRes <- result{nil}
	}()

	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// trxInstallReverseProxy installs reverseproxy
func (instance *Cluster) trxInstallReverseProxy(inctx context.Context, clusterTrx clusterTransaction, params data.Map[string, any]) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		identity, xerr := trxGetIdentity(ctx, clusterTrx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		dockerDisabled := false
		xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
			_, dockerDisabled = featuresV1.Disabled["docker"]
			return nil
		})
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		if dockerDisabled {
			chRes <- result{nil}
			return
		}

		clusterName := identity.Name
		disabled := false
		xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
			_, disabled = featuresV1.Disabled["reverseproxy"]
			return nil
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		if !disabled {
			logrus.WithContext(ctx).Debugf("[Cluster %s] adding feature 'edgeproxy4subnet'", clusterName)
			feat, xerr := NewFeature(ctx, "edgeproxy4subnet")
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			// params, _ := data.FromMap(params)
			results, xerr := feat.Add(ctx, instance, params)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			if !results.IsSuccessful() {
				chRes <- result{fail.NewError("[Cluster %s] failed to add '%s': %s", clusterName, feat.GetName(), results.ErrorMessage())}
				return
			}

			xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
				featuresV1.Installed[feat.GetName()] = &propertiesv1.ClusterInstalledFeature{
					Name: feat.GetName(),
				}
				return nil
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
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// trxInstallRemoteDesktop installs feature remotedesktop on all masters of the Cluster
func (instance *Cluster) trxInstallRemoteDesktop(inctx context.Context, clusterTrx clusterTransaction, params data.Map[string, any]) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		identity, xerr := trxGetIdentity(ctx, clusterTrx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		dockerDisabled := false
		xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
			_, dockerDisabled = featuresV1.Disabled["docker"]
			return nil
		})
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		if dockerDisabled {
			chRes <- result{nil}
			return
		}

		disabled := false
		xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
			_, disabled = featuresV1.Disabled["remotedesktop"]
			return nil
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		if !disabled {
			logrus.WithContext(ctx).Debugf("[Cluster %s] adding feature 'remotedesktop'", identity.Name)

			feat, xerr := NewFeature(ctx, "remotedesktop")
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			// Adds remotedesktop feature on Cluster (ie masters)
			// params, _ := data.FromMap(params)
			params["Username"] = "cladm"
			params["Password"] = identity.AdminPassword

			// FIXME: Bug mitigations
			params["GuacamolePort"] = 63011
			params["TomcatPort"] = 9009

			r, xerr := feat.Add(ctx, instance, params)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			if !r.IsSuccessful() {
				xerr = fail.NewError("[Cluster %s] failed to add 'remotedesktop' failed: %s", identity.Name, r.ErrorMessage())
				_ = xerr.Annotate("ran_but_failed", true)
				chRes <- result{xerr}
				return
			}

			xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
				featuresV1.Installed["remotedesktop"] = &propertiesv1.ClusterInstalledFeature{
					Name: "remotedesktop",
				}
				return nil
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
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// trxInstallAnsible installs feature ansible on all masters of the Cluster
func (instance *Cluster) trxInstallAnsible(inctx context.Context, clusterTrx clusterTransaction, params data.Map[string, any]) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		identity, xerr := trxGetIdentity(ctx, clusterTrx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		disabled := false
		xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
			_, disabled = featuresV1.Disabled["ansible"]
			return nil
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
			feat, xerr := NewFeature(ctx, "ansible")
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			// Adds ansible feature on Cluster (ie masters)
			// params, _ := data.FromMap(params)
			params["Username"] = "cladm"
			params["Password"] = identity.AdminPassword
			r, xerr := feat.Add(ctx, instance, params)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			if !r.IsSuccessful() {
				chRes <- result{fail.NewError("[Cluster %s] failed to add 'ansible': %s", identity.Name, r.ErrorMessage())}
				return
			}
			logrus.WithContext(ctx).Debugf("[Cluster %s] feature 'ansible' added successfully", identity.Name)

			// 2nd, Feature 'ansible-for-cluster' (which does the necessary for a dynamic inventory)
			feat, xerr = NewFeature(ctx, "ansible-for-cluster")
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			r, xerr = feat.Add(ctx, instance, params)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			if !r.IsSuccessful() {
				chRes <- result{fail.NewError("[Cluster %s] failed to add 'ansible-for-cluster': %s", identity.Name, r.ErrorMessage())}
				return
			}

			xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
				featuresV1.Installed["ansible-for-cluster"] = &propertiesv1.ClusterInstalledFeature{
					Name: "ansible-for-cluster",
				}
				return nil
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
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// trxInstallDocker installs docker and docker-compose
func (instance *Cluster) trxInstallDocker(inctx context.Context, clusterTrx clusterTransaction, host *Host, hostLabel string, params data.Map[string, any]) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		dockerDisabled := false
		xerr := inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
			_, dockerDisabled = featuresV1.Disabled["docker"]
			return nil
		})
		if xerr != nil {
			xerr = fail.Wrap(xerr, callstack.WhereIsThis())
			chRes <- result{xerr}
			return
		}

		if dockerDisabled {
			chRes <- result{nil}
			return
		}

		// uses NewFeature() to let a chance to the user to use its own docker feature
		feat, xerr := NewFeature(ctx, "docker")
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		// params, _ := data.FromMap(params)
		r, xerr := feat.Add(ctx, host, params)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		reason := false
		if !r.IsSuccessful() {
			keys, xerr := r.Keys()
			if xerr != nil {
				chRes <- result{xerr}
				return
			}
			for _, k := range keys {
				rk, xerr := r.PayloadOf(k)
				if xerr != nil {
					chRes <- result{xerr}
					return
				}

				if !rk.IsSuccessful() {
					msg := rk.ErrorMessage()
					if len(msg) == 0 {
						logrus.WithContext(ctx).Warnf("This is a false warning for %s !!: %s", k, msg)
					} else {
						reason = true
						logrus.WithContext(ctx).Warnf("This failed: %s with %s", k, spew.Sdump(rk))
					}
				}
			}

			if reason {
				chRes <- result{fail.NewError("[%s] failed to add feature 'docker' on host '%s': %s", hostLabel, host.GetName(), r.ErrorMessage())}
				return
			}
		}

		xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
			featuresV1.Installed[feat.GetName()] = &propertiesv1.ClusterInstalledFeature{
				Name: feat.GetName(),
			}
			return nil
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
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}
