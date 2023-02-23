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

// // TargetType returns the type of the target
// //
// // satisfies resources.Targetable interface
// func (instance *Cluster) TargetType() featuretargettype.Enum {
// 	return featuretargettype.Cluster
// }

//
// // InstallMethods returns a list of installation methods usable on the target, ordered from upper to lower preference (1 = the highest preference)
// // satisfies resources.Targetable interface
// func (instance *Cluster) InstallMethods(ctx context.Context) (_ map[uint8]installmethod.Enum, ferr fail.Error) {
// 	if valid.IsNil(instance) {
// 		return nil, fail.InvalidInstanceError()
// 	}
// 	if ctx == nil {
// 		return nil, fail.InvalidParameterCannotBeNilError("ctx")
// 	}
//
// 	out := make(map[uint8]installmethod.Enum)
//
// 	clusterTrx, xerr := newClusterTransaction(ctx, instance)
// 	if xerr != nil {
// 		return out, nil
// 	}
// 	defer clusterTrx.TerminateFromError(ctx, &ferr)
//
// 	incrementExpVar("cluster.cache.hit")
// 	return out, inspectClusterMetadataAbstract(ctx, clusterTrx, func(aci *abstract.Cluster) fail.Error {
// 		aci.Local.InstallMethods.Range(func(k, v interface{}) bool {
// 			var ok bool
// 			out[k.(uint8)], ok = v.(installmethod.Enum)
// 			return ok
// 		})
// 		return nil
// 	})
// }
//
// // InstalledFeatures returns a list of installed features
// func (instance *Cluster) InstalledFeatures(ctx context.Context) (_ []string, ferr fail.Error) {
// 	if valid.IsNull(instance) {
// 		return []string{}, fail.InvalidInstanceError()
// 	}
//
// 	clusterTrx, xerr := newClusterTransaction(ctx, instance)
// 	if xerr != nil {
// 		return nil, xerr
// 	}
// 	defer clusterTrx.TerminateFromError(ctx, &ferr)
//
// 	var out []string
// 	xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.FeaturesV1, func(p clonable.Clonable) fail.Error {
// 		featuresV1, innerErr := lang.Cast[*propertiesv1.ClusterFeatures](p)
// 		if innerErr != nil {
// 			return fail.Wrap(innerErr)
// 		}
//
// 		for k := range featuresV1.Installed {
// 			out = append(out, k)
// 		}
// 		return nil
// 	})
// 	xerr = debug.InjectPlannedFail(xerr)
// 	if xerr != nil {
// 		return []string{}, xerr
// 	}
// 	return out, nil
// }
//
// // ComplementFeatureParameters configures parameters that are implicitly defined, based on target
// // satisfies interface resources.Targetable
// func (instance *Cluster) ComplementFeatureParameters(inctx context.Context, v data.Map[string, any]) (ferr fail.Error) {
// 	if valid.IsNil(instance) {
// 		return fail.InvalidInstanceError()
// 	}
//
// 	ctx, cancel := context.WithCancel(inctx)
// 	defer cancel()
//
// 	clusterTrx, xerr := newClusterTransaction(ctx, instance)
// 	if xerr != nil {
// 		return xerr
// 	}
// 	defer clusterTrx.TerminateFromError(ctx, &ferr)
//
// 	identity, xerr := clusterTrx.getAbstract(ctx)
// 	xerr = debug.InjectPlannedFail(xerr)
// 	if xerr != nil {
// 		return xerr
// 	}
//
// 	v["ClusterComplexity"] = strings.ToLower(identity.Complexity.String())
// 	v["ClusterFlavor"] = strings.ToLower(identity.Flavor.String())
// 	v["ClusterName"] = identity.Name
// 	v["ClusterAdminUsername"] = "cladm"
// 	v["ClusterAdminPassword"] = identity.AdminPassword
// 	if _, ok := v["Username"]; !ok {
// 		config, xerr := instance.Service().ConfigurationOptions()
// 		if xerr != nil {
// 			return xerr
// 		}
// 		v["Username"] = config.OperatorUsername
// 		if v["username"] == "" {
// 			v["Username"] = abstract.DefaultUser
// 		}
// 	}
// 	networkCfg, xerr := instance.NetworkConfig(ctx)
// 	xerr = debug.InjectPlannedFail(xerr)
// 	if xerr != nil {
// 		return xerr
// 	}
//
// 	v["PrimaryGatewayIP"] = networkCfg.GatewayIP
// 	v["DefaultRouteIP"] = networkCfg.DefaultRouteIP
// 	v["GatewayIP"] = v["DefaultRouteIP"] // legacy ...
// 	v["PrimaryPublicIP"] = networkCfg.PrimaryPublicIP
// 	v["NetworkUsesVIP"] = networkCfg.SecondaryGatewayIP != ""
// 	v["SecondaryGatewayIP"] = networkCfg.SecondaryGatewayIP
// 	v["SecondaryPublicIP"] = networkCfg.SecondaryPublicIP
// 	v["EndpointIP"] = networkCfg.EndpointIP
// 	v["PublicIP"] = v["EndpointIP"] // legacy ...
// 	if _, ok := v["IPRanges"]; !ok {
// 		v["IPRanges"] = networkCfg.CIDR
// 	}
// 	v["CIDR"] = networkCfg.CIDR
//
// 	var cpV1 *propertiesv1.ClusterControlplane
// 	xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.ControlPlaneV1, func(controlPlaneV1 *propertiesv1.ClusterControlplane) fail.Error {
// 		cpV1 = controlPlaneV1
// 		return nil
// 	})
// 	xerr = debug.InjectPlannedFail(xerr)
// 	if xerr != nil {
// 		return xerr
// 	}
//
// 	if cpV1.VirtualIP != nil && cpV1.VirtualIP.PrivateIP != "" {
// 		v["ClusterControlplaneUsesVIP"] = true
// 		v["ClusterControlplaneEndpointIP"] = cpV1.VirtualIP.PrivateIP
// 	} else {
// 		// Don't set ClusterControlplaneUsesVIP if there is no VIP... use IP of first available master instead
// 		master, xerr := clusterTrx.FindAvailableMaster(ctx)
// 		xerr = debug.InjectPlannedFail(xerr)
// 		if xerr != nil {
// 			return xerr
// 		}
//
// 		v["ClusterControlplaneEndpointIP"], xerr = master.GetPrivateIP(ctx)
// 		xerr = debug.InjectPlannedFail(xerr)
// 		if xerr != nil {
// 			return xerr
// 		}
//
// 		v["ClusterControlplaneUsesVIP"] = false
// 	}
// 	v["ClusterMasters"], xerr = clusterTrx.ListMasters(ctx)
// 	xerr = debug.InjectPlannedFail(xerr)
// 	if xerr != nil {
// 		return xerr
// 	}
//
// 	list := make([]string, 0, len(v["ClusterMasters"].(rscapi.IndexedListOfClusterNodes)))
// 	for _, v := range v["ClusterMasters"].(rscapi.IndexedListOfClusterNodes) {
// 		list = append(list, v.Name)
// 	}
// 	v["ClusterMasterNames"] = list
//
// 	list = make([]string, 0, len(v["ClusterMasters"].(rscapi.IndexedListOfClusterNodes)))
// 	for _, v := range v["ClusterMasters"].(rscapi.IndexedListOfClusterNodes) {
// 		list = append(list, v.ID)
// 	}
// 	v["ClusterMasterIDs"] = list
//
// 	v["ClusterMasterIPs"], xerr = clusterTrx.ListMasterIPs(ctx)
// 	xerr = debug.InjectPlannedFail(xerr)
// 	if xerr != nil {
// 		return xerr
// 	}
//
// 	v["ClusterNodes"], xerr = clusterTrx.ListNodes(ctx)
// 	xerr = debug.InjectPlannedFail(xerr)
// 	if xerr != nil {
// 		return xerr
// 	}
//
// 	list = make([]string, 0, len(v["ClusterNodes"].(rscapi.IndexedListOfClusterNodes)))
// 	for _, v := range v["ClusterNodes"].(rscapi.IndexedListOfClusterNodes) {
// 		list = append(list, v.Name)
// 	}
// 	v["ClusterNodeNames"] = list
//
// 	list = make([]string, 0, len(v["ClusterNodes"].(rscapi.IndexedListOfClusterNodes)))
// 	for _, v := range v["ClusterNodes"].(rscapi.IndexedListOfClusterNodes) {
// 		list = append(list, v.ID)
// 	}
// 	v["ClusterNodeIDs"] = list
//
// 	v["ClusterNodeIPs"], xerr = clusterTrx.ListNodeIPs(ctx)
// 	xerr = debug.InjectPlannedFail(xerr)
// 	if xerr != nil {
// 		return xerr
// 	}
//
// 	return nil
// }
//
// // RegisterFeature registers an installed Feature in metadata of a Cluster
// // satisfies interface resources.Targetable
// func (instance *Cluster) RegisterFeature(ctx context.Context, feat *Feature, requiredBy *Feature, clusterContext bool) (ferr fail.Error) {
// 	defer fail.OnPanic(&ferr)
//
// 	if valid.IsNil(instance) {
// 		return fail.InvalidInstanceError()
// 	}
// 	if feat == nil {
// 		return fail.InvalidParameterError("feat", "cannot be null value of '*Feature'")
// 	}
//
// 	trx, xerr := newClusterTransaction(ctx, instance)
// 	if xerr != nil {
// 		return xerr
// 	}
// 	defer trx.TerminateFromError(ctx, &ferr)
//
// 	return alterClusterMetadataProperty(ctx, trx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
// 		item, ok := featuresV1.Installed[feat.GetName()]
// 		if !ok {
// 			requirements, innerXErr := feat.Dependencies(ctx)
// 			if innerXErr != nil {
// 				return innerXErr
// 			}
//
// 			item = propertiesv1.NewClusterInstalledFeature()
// 			item.Name = feat.GetName()
// 			item.FileName = feat.GetDisplayFilename(ctx)
// 			item.Requires = requirements
// 			featuresV1.Installed[item.Name] = item
// 		}
// 		if !valid.IsNil(requiredBy) {
// 			item.RequiredBy[requiredBy.GetName()] = struct{}{}
// 		}
// 		return nil
// 	})
// }
//
// // UnregisterFeature unregisters a Feature from Cluster metadata
// // satisfies interface resources.Targetable
// func (instance *Cluster) UnregisterFeature(inctx context.Context, feat string) (ferr fail.Error) {
// 	defer fail.OnPanic(&ferr)
//
// 	if valid.IsNil(instance) {
// 		return fail.InvalidInstanceError()
// 	}
// 	if feat == "" {
// 		return fail.InvalidParameterError("feat", "cannot be empty string")
// 	}
//
// 	ctx, cancel := context.WithCancel(inctx)
// 	defer cancel()
//
// 	trx, xerr := newClusterTransaction(ctx, instance)
// 	if xerr != nil {
// 		return xerr
// 	}
// 	defer trx.TerminateFromError(ctx, &ferr)
//
// 	xerr = alterClusterMetadataProperty(ctx, trx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
// 		delete(featuresV1.Installed, feat)
// 		for _, v := range featuresV1.Installed {
// 			delete(v.RequiredBy, feat)
// 		}
// 		return nil
// 	})
// 	if xerr != nil {
// 		xerr = fail.Wrap(xerr, callstack.WhereIsThis())
// 	}
// 	return xerr
// }

// // AddFeature installs a feature on the Cluster
// func (instance *Cluster) AddFeature(ctx context.Context, name string, vars data.Map[string, any], opts ...options.Option) (_ rscapi.Results, ferr fail.Error) {
// 	if valid.IsNil(instance) {
// 		return nil, fail.InvalidInstanceError()
// 	}
// 	if ctx == nil {
// 		return nil, fail.InvalidParameterCannotBeNilError("ctx")
// 	}
// 	if name == "" {
// 		return nil, fail.InvalidParameterError("name", "cannot be empty string")
// 	}
//
// 	feat, xerr := NewFeature(ctx, name)
// 	xerr = debug.InjectPlannedFail(xerr)
// 	if xerr != nil {
// 		return nil, xerr
// 	}
//
// 	clusterTrx, xerr := newClusterTransaction(ctx, instance)
// 	if xerr != nil {
// 		return nil, xerr
// 	}
// 	defer clusterTrx.TerminateFromError(ctx, &ferr)
//
// 	return feat.Add(ctx, clusterTrx, vars, opts...)
// }

// // CheckFeature tells if a feature is installed on the Cluster
// func (instance *Cluster) CheckFeature(ctx context.Context, name string, vars data.Map[string, any], opts ...options.Option) (_ rscapi.Results, ferr fail.Error) {
// 	if valid.IsNil(instance) {
// 		return nil, fail.InvalidInstanceError()
// 	}
// 	if name == "" {
// 		return nil, fail.InvalidParameterError("name", "cannot be empty string")
// 	}
// 	if ctx == nil {
// 		return nil, fail.InvalidParameterCannotBeNilError("ctx")
// 	}
//
// 	feat, xerr := NewFeature(ctx, name)
// 	xerr = debug.InjectPlannedFail(xerr)
// 	if xerr != nil {
// 		return nil, xerr
// 	}
//
// 	clusterTrx, xerr := newClusterTransaction(ctx, instance)
// 	if xerr != nil {
// 		return nil, xerr
// 	}
// 	defer clusterTrx.TerminateFromError(ctx, &ferr)
//
// 	return feat.Check(ctx, clusterTrx, vars, opts...)
// }

// // RemoveFeature uninstalls a feature from the Cluster
// func (instance *Cluster) RemoveFeature(ctx context.Context, name string, vars data.Map[string, any], opts ...options.Option) (_ rscapi.Results, ferr fail.Error) {
// 	if valid.IsNil(instance) {
// 		return nil, fail.InvalidInstanceError()
// 	}
// 	if name == "" {
// 		return nil, fail.InvalidParameterError("name", "cannot be empty string")
// 	}
// 	if ctx == nil {
// 		return nil, fail.InvalidParameterCannotBeNilError("ctx")
// 	}
//
// 	feat, xerr := NewFeature(ctx, name)
// 	xerr = debug.InjectPlannedFail(xerr)
// 	if xerr != nil {
// 		return nil, xerr
// 	}
//
// 	clusterTrx, xerr := newClusterTransaction(ctx, instance)
// 	if xerr != nil {
// 		return nil, xerr
// 	}
// 	defer clusterTrx.TerminateFromError(ctx, &ferr)
//
// 	return feat.Remove(ctx, clusterTrx, vars, opts...)
// }
