package operations

import (
	"context"
	"fmt"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v3"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/eko/gocache/v2/store"
	"github.com/sirupsen/logrus"
	"reflect"
	"strings"
	"time"
)

func LoadHost(inctx context.Context, svc iaas.Service, ref string) (resources.Host, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	lock, xerr := svc.GetLock(abstract.HostResource)
	if xerr != nil {
		return nil, xerr
	}

	lock.Lock()
	defer lock.Unlock()

	return loadHost(inctx, svc, ref)
}

// LoadHost ...
func loadHost(inctx context.Context, svc iaas.Service, ref string) (resources.Host, fail.Error) {
	defer elapsed(inctx, fmt.Sprintf("LoadHost of %s", ref))()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		a    resources.Host
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		ga, gerr := func() (_ resources.Host, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			if svc == nil {
				return nil, fail.InvalidParameterCannotBeNilError("svc")
			}
			if ref == "" {
				return nil, fail.InvalidParameterCannotBeEmptyStringError("ref")
			}

			// trick to avoid collisions
			var kt *Host
			refcache := fmt.Sprintf("%T/%s", kt, ref)

			cache, xerr := svc.GetCache(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				if val, xerr := cache.Get(ctx, refcache); xerr == nil {
					casted, ok := val.(resources.Host)
					if ok {
						incrementExpVar("host.cache.hit")
						return casted, nil
					} else {
						logrus.WithContext(ctx).Warnf("wrong type of resources.Host")
					}
				} else {
					logrus.WithContext(ctx).Warnf("loadhost host cache response (%s): %v", refcache, xerr)
				}
			}

			anon, xerr := onHostCacheMiss(ctx, svc, ref)
			if xerr != nil {
				return nil, xerr
			}

			incrementExpVar("newhost.cache.hit")
			hostInstance, ok := anon.(*Host)
			if !ok {
				return nil, fail.InconsistentError("cache content for key %s is not a resources.Host", ref)
			}
			if hostInstance == nil {
				return nil, fail.InconsistentError("nil value found in Host cache for key '%s'", ref)
			}

			// if cache failed we are here, so we better retrieve updated information...
			xerr = hostInstance.Reload(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				hid, err := hostInstance.GetID()
				if err != nil {
					return nil, fail.ConvertError(err)
				}

				err = cache.Set(ctx, refcache, hostInstance, &store.Options{Expiration: 120 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}

				err = cache.Set(ctx, fmt.Sprintf("%T/%s", kt, hostInstance.GetName()), hostInstance, &store.Options{Expiration: 120 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}

				err = cache.Set(ctx, fmt.Sprintf("%T/%s", kt, hid), hostInstance, &store.Options{Expiration: 120 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				time.Sleep(100 * time.Millisecond) // consolidate cache.Set

				if val, xerr := cache.Get(ctx, refcache); xerr == nil {
					casted, ok := val.(resources.Host)
					if ok {
						incrementExpVar("host.cache.hit")
						return casted, nil
					} else {
						logrus.WithContext(ctx).Warnf("wrong type of resources.Host")
					}
				} else {
					logrus.WithContext(ctx).Warnf("host cache response (%s): %v", refcache, xerr)
				}

			}

			return hostInstance, nil
		}()
		chRes <- result{ga, gerr}
	}()
	select {
	case res := <-chRes:
		return res.a, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

func LoadLabel(inctx context.Context, svc iaas.Service, ref string) (resources.Label, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	lock, xerr := svc.GetLock(abstract.LabelResource)
	if xerr != nil {
		return nil, xerr
	}

	lock.Lock()
	defer lock.Unlock()

	return loadLabel(inctx, svc, ref)
}

// LoadLabel loads the metadata of a Label
func loadLabel(inctx context.Context, svc iaas.Service, ref string) (resources.Label, fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  resources.Label
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		ga, gerr := func() (_ resources.Label, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			if svc == nil {
				return nil, fail.InvalidParameterCannotBeNilError("svc")
			}
			if ref = strings.TrimSpace(ref); ref == "" {
				return nil, fail.InvalidParameterCannotBeEmptyStringError("ref")
			}

			// trick to avoid collisions
			var kt *label
			cacheref := fmt.Sprintf("%T/%s", kt, ref)

			cache, xerr := svc.GetCache(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				if val, xerr := cache.Get(ctx, cacheref); xerr == nil {
					casted, ok := val.(resources.Label)
					if ok {
						return casted, nil
					}
				}
			}

			cacheMissLoader := func() (data.Identifiable, fail.Error) { return onLabelCacheMiss(ctx, svc, ref) }
			anon, xerr := cacheMissLoader()
			if xerr != nil {
				return nil, xerr
			}

			labelInstance, ok := anon.(resources.Label)
			if !ok {
				return nil, fail.InconsistentError("value in cache for Label with key '%s' is not a resources.Label", ref)
			}
			if labelInstance == nil {
				return nil, fail.InconsistentError("nil value in cache for Label with key '%s'", ref)
			}

			// if cache failed we are here, so we better retrieve updated information...
			xerr = labelInstance.Reload(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				err := cache.Set(ctx, fmt.Sprintf("%T/%s", kt, labelInstance.GetName()), labelInstance, &store.Options{Expiration: 120 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				time.Sleep(50 * time.Millisecond) // consolidate cache.Set
				hid, err := labelInstance.GetID()
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				err = cache.Set(ctx, fmt.Sprintf("%T/%s", kt, hid), labelInstance, &store.Options{Expiration: 120 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				time.Sleep(50 * time.Millisecond) // consolidate cache.Set

				if val, xerr := cache.Get(ctx, cacheref); xerr == nil {
					casted, ok := val.(resources.Label)
					if ok {
						return casted, nil
					} else {
						logrus.WithContext(ctx).Warnf("wrong type of resources.Label")
					}
				} else {
					logrus.WithContext(ctx).Warnf("label cache response (%s): %v", cacheref, xerr)
				}
			}

			return labelInstance, nil
		}()
		chRes <- result{ga, gerr}
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

func LoadFeatureFile(inctx context.Context, svc iaas.Service, ref string, emb bool) (*FeatureFile, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	lock, xerr := svc.GetLock(abstract.FeatureResource)
	if xerr != nil {
		return nil, xerr
	}

	lock.Lock()
	defer lock.Unlock()

	return loadFeatureFile(inctx, svc, ref, emb)
}

// loadFeatureFile searches for a spec file named 'name' and initializes a new FeatureFile object
// with its content
// 'xerr' may contain:
//   - nil: everything worked as expected
//   - fail.ErrNotFound: no FeatureFile is found with the name
//   - fail.ErrSyntax: FeatureFile contains syntax error
func loadFeatureFile(inctx context.Context, svc iaas.Service, name string, embeddedOnly bool) (*FeatureFile, fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  *FeatureFile
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		ga, gerr := func() (_ *FeatureFile, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			if svc == nil {
				return nil, fail.InvalidParameterCannotBeNilError("svc")
			}
			if name == "" {
				return nil, fail.InvalidParameterError("name", "cannot be empty string")
			}

			// trick to avoid collisions
			var kt *FeatureFile
			cachename := fmt.Sprintf("%T/%s", kt, name)

			cache, xerr := svc.GetCache(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				if val, xerr := cache.Get(ctx, cachename); xerr == nil {
					casted, ok := val.(*FeatureFile)
					if ok {
						incrementExpVar("newhost.cache.hit")
						return casted, nil
					}
				}
			}

			cacheMissLoader := func() (data.Identifiable, fail.Error) { return onFeatureFileCacheMiss(svc, name, embeddedOnly) }
			anon, xerr := cacheMissLoader()
			if xerr != nil {
				return nil, xerr
			}

			featureFileInstance, ok := anon.(*FeatureFile)
			if !ok {
				return nil, fail.InconsistentError("cache content for key '%s' is not a resources.Feature", name)
			}
			if featureFileInstance == nil {
				return nil, fail.InconsistentError("nil value found in Feature cache for key '%s'", name)
			}

			if cache != nil {
				err := cache.Set(ctx, fmt.Sprintf("%T/%s", kt, featureFileInstance.GetName()), featureFileInstance, &store.Options{Expiration: 120 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				time.Sleep(50 * time.Millisecond) // consolidate cache.Set
				hid, err := featureFileInstance.GetID()
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				err = cache.Set(ctx, fmt.Sprintf("%T/%s", kt, hid), featureFileInstance, &store.Options{Expiration: 120 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				time.Sleep(50 * time.Millisecond) // consolidate cache.Set

				if val, xerr := cache.Get(ctx, cachename); xerr == nil {
					casted, ok := val.(*FeatureFile)
					if ok {
						return casted, nil
					} else {
						logrus.WithContext(ctx).Warnf("wrong type of resources.FeatureFile")
					}
				} else {
					logrus.WithContext(ctx).Warnf("feature cache response (%s): %v", cachename, xerr)
				}
			}

			return featureFileInstance, nil
		}()
		chRes <- result{ga, gerr}
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

func LoadCluster(inctx context.Context, svc iaas.Service, ref string) (resources.Cluster, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	lock, xerr := svc.GetLock(abstract.ClusterResource)
	if xerr != nil {
		return nil, xerr
	}

	lock.Lock()
	defer lock.Unlock()

	return loadCluster(inctx, svc, ref)
}

// LoadCluster loads cluster information from metadata
func loadCluster(inctx context.Context, svc iaas.Service, name string) (_ resources.Cluster, ferr fail.Error) {
	defer elapsed(inctx, "LoadCluster")()
	defer fail.OnPanic(&ferr)

	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}
	if name = strings.TrimSpace(name); name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  resources.Cluster
		rErr fail.Error
	}

	chRes := make(chan result)
	go func() {
		defer close(chRes)

		// trick to avoid collisions
		var kt *Cluster
		cachename := fmt.Sprintf("%T/%s", kt, name)

		cache, xerr := svc.GetCache(ctx)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		if cache != nil {
			if val, xerr := cache.Get(ctx, cachename); xerr == nil {
				casted, ok := val.(resources.Cluster)
				if ok {
					chRes <- result{casted, nil}
					return
				}
			}
		}

		cacheMissLoader := func() (data.Identifiable, fail.Error) { return onClusterCacheMiss(ctx, svc, name) }
		anon, xerr := cacheMissLoader()
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		var (
			clusterInstance *Cluster
			ok              bool
		)
		if clusterInstance, ok = anon.(*Cluster); !ok {
			chRes <- result{nil, fail.InconsistentError("value found in Cluster cache for key '%s' is not a Cluster", name)}
			return
		}
		if clusterInstance == nil {
			chRes <- result{nil, fail.InconsistentError("nil value found in Cluster cache for key '%s'", name)}
			return
		}

		if clusterInstance.randomDelayCh == nil {
			xerr = clusterInstance.startRandomDelayGenerator(ctx, 0, 2000)
			if xerr != nil {
				chRes <- result{nil, xerr}
				return
			}
		}

		// if cache failed we are here, so we better retrieve updated information...
		xerr = clusterInstance.Reload(ctx)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		if cache != nil {
			err := cache.Set(ctx, fmt.Sprintf("%T/%s", kt, clusterInstance.GetName()), clusterInstance, &store.Options{Expiration: 120 * time.Minute})
			if err != nil {
				chRes <- result{nil, fail.ConvertError(err)}
				return
			}
			hid, err := clusterInstance.GetID()
			if err != nil {
				chRes <- result{nil, fail.ConvertError(err)}
				return
			}
			err = cache.Set(ctx, fmt.Sprintf("%T/%s", kt, hid), clusterInstance, &store.Options{Expiration: 120 * time.Minute})
			if err != nil {
				chRes <- result{nil, fail.ConvertError(err)}
				return
			}
			time.Sleep(100 * time.Millisecond) // consolidate cache.Set

			if val, xerr := cache.Get(ctx, cachename); xerr == nil {
				casted, ok := val.(resources.Cluster)
				if ok {
					chRes <- result{casted, nil}
					return
				} else {
					logrus.WithContext(ctx).Warnf("wrong type of resources.Host")
				}
			} else {
				logrus.WithContext(ctx).Warnf("cluster cache response (%s): %v", cachename, xerr)
			}
		}

		xerr = clusterInstance.updateCachedInformation(ctx)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		// And now prevent useless metadata trickery here...
		shi, err := clusterInstance.MetadataCore.shielded.UnWrap()
		if err != nil {
			chRes <- result{nil, fail.ConvertError(err)}
			return
		}

		aclu, ok := shi.(*abstract.ClusterIdentity)
		if !ok {
			chRes <- result{nil, fail.NewError("bad cast")}
			return
		}
		clusterInstance.cluID = aclu

		aclupro, err := clusterInstance.MetadataCore.properties.UnWrap()
		if err != nil {
			chRes <- result{nil, fail.ConvertError(err)}
			return
		}

		flavor, xerr := clusterInstance.GetFlavor(ctx)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		xerr = clusterInstance.bootstrap(flavor)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		if val, ok := aclupro[clusterproperty.NodesV3]; !ok {
			chRes <- result{nil, fail.NewError("corrupted metadata")}
			return
		} else {
			if val == nil {
				chRes <- result{nil, fail.NewError("corrupted metadata")}
				return
			}
		}

		foo, err := aclupro[clusterproperty.NodesV3].UnWrap()
		if err != nil {
			chRes <- result{nil, fail.ConvertError(err)}
			return
		}

		gotta, ok := foo.(*propertiesv3.ClusterNodes)
		if !ok {
			chRes <- result{nil, fail.NewError("bad cast")}
			return
		}
		for k := range gotta.PrivateNodeByID {
			clusterInstance.nodes = append(clusterInstance.nodes, k)
		}
		for k := range gotta.MasterByID {
			clusterInstance.masters = append(clusterInstance.masters, k)
		}

		if val, ok := aclupro[clusterproperty.StateV1]; !ok {
			chRes <- result{nil, fail.NewError("corrupted metadata")}
			return
		} else {
			if val == nil {
				chRes <- result{nil, fail.NewError("corrupted metadata")}
				return
			}
		}

		asta, err := aclupro[clusterproperty.StateV1].UnWrap()
		if err != nil {
			chRes <- result{nil, fail.ConvertError(err)}
			return
		}

		gurb, ok := asta.(*propertiesv1.ClusterState)
		if !ok {
			chRes <- result{nil, fail.NewError("bad cast")}
			return
		}

		clusterInstance.state = gurb.State

		for k, v := range gotta.ByNumericalID {
			if strings.Contains(v.Name, "node") {
				clusterInstance.nodeIPs[k] = v.PrivateIP
			}
			if strings.Contains(v.Name, "master") {
				clusterInstance.masterIPs[k] = v.PrivateIP
			}
		}

		chRes <- result{clusterInstance, nil}
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

func LoadSubnet(inctx context.Context, svc iaas.Service, networkRef, sunetRef string) (*Subnet, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	lock, xerr := svc.GetLock(abstract.SubnetResource)
	if xerr != nil {
		return nil, xerr
	}

	lock.Lock()
	defer lock.Unlock()

	return loadSubnet(inctx, svc, networkRef, sunetRef)
}

// LoadSubnet loads the metadata of a Subnet
func loadSubnet(inctx context.Context, svc iaas.Service, networkRef, subnetRef string) (*Subnet, fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  *Subnet
		rErr fail.Error
	}

	chRes := make(chan result)
	go func() {
		defer close(chRes)
		ga, gerr := func() (_ *Subnet, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			if svc == nil {
				return nil, fail.InvalidParameterCannotBeNilError("svc")
			}
			if subnetRef = strings.TrimSpace(subnetRef); subnetRef == "" {
				return nil, fail.InvalidParameterError("subnetRef", "cannot be empty string")
			}

			// trick to avoid collisions
			var kt *Subnet
			cachesubnetRef := fmt.Sprintf("%T/%s", kt, subnetRef)

			cache, xerr := svc.GetCache(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				if val, xerr := cache.Get(ctx, cachesubnetRef); xerr == nil {
					casted, ok := val.(*Subnet)
					if ok {
						return casted, nil
					}
				}
			}

			// -- First step: identify subnetID from (networkRef, subnetRef) --
			var (
				subnetID        string
				networkInstance resources.Network
			)

			networkRef = strings.TrimSpace(networkRef)
			switch networkRef {
			case "":
				// If networkRef is empty, subnetRef must be subnetID
				subnetID = subnetRef
			default:
				// Try to load Network metadata
				networkInstance, xerr = LoadNetwork(ctx, svc, networkRef)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						debug.IgnoreError2(ctx, xerr)
						// Network metadata can be missing if it's the default Network, so continue
					default:
						return nil, xerr
					}
				}

				withDefaultSubnetwork, err := svc.HasDefaultNetwork(ctx)
				if err != nil {
					return nil, err
				}

				if networkInstance != nil { // nolint
					// Network metadata loaded, find the ID of the Subnet (subnetRef may be ID or Name)
					xerr = networkInstance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
						return props.Inspect(networkproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
							subnetsV1, ok := clonable.(*propertiesv1.NetworkSubnets)
							if !ok {
								return fail.InconsistentError("'*propertiesv1.NetworkSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
							}

							var found bool
							for k, v := range subnetsV1.ByName {
								if k == subnetRef || v == subnetRef {
									subnetID = v
									found = true
									break
								}
							}
							if !found {
								return fail.NotFoundError("failed to find a Subnet referenced by '%s' in network '%s'", subnetRef, networkInstance.GetName())
							}
							return nil
						})
					})
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						return nil, xerr
					}
				} else if withDefaultSubnetwork {
					// No Network Metadata, try to use the default Network if there is one
					an, xerr := svc.GetDefaultNetwork(ctx)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						return nil, xerr
					}

					if an.Name == networkRef || an.ID == networkRef {
						// We are in default Network context, query Subnet list and search for the one requested
						list, xerr := ListSubnets(ctx, svc, an.ID, false)
						xerr = debug.InjectPlannedFail(xerr)
						if xerr != nil {
							return nil, xerr
						}

						for _, v := range list {
							if v.ID == subnetRef || v.Name == subnetRef {
								subnetID = v.ID
								break
							}
						}
					}
				} else {
					// failed to identify the Network owning the Subnets
					return nil, fail.NotFoundError("failed to find Network '%s'", networkRef)
				}
			}

			if subnetID == "" {
				return nil, fail.NotFoundError("failed to find a Subnet '%s' in Network '%s'", subnetRef, networkRef)
			}

			// -- second step: search instance in service cache
			cacheMissLoader := func() (data.Identifiable, fail.Error) { return onSubnetCacheMiss(ctx, svc, subnetID) }
			anon, xerr := cacheMissLoader()
			if xerr != nil {
				return nil, xerr
			}

			var ok bool
			subnetInstance, ok := anon.(*Subnet)
			if !ok {
				return nil, fail.InconsistentError("cache entry for %s is not a *Subnet", subnetID)
			}
			if subnetInstance == nil {
				return nil, fail.InconsistentError("nil found in cache for Subnet with id %s", subnetID)
			}

			// if cache failed we are here, so we better retrieve updated information...
			xerr = subnetInstance.Reload(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				err := cache.Set(ctx, fmt.Sprintf("%T/%s", kt, subnetInstance.GetName()), subnetInstance, &store.Options{Expiration: 120 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				hid, err := subnetInstance.GetID()
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				err = cache.Set(ctx, fmt.Sprintf("%T/%s", kt, hid), subnetInstance, &store.Options{Expiration: 120 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				time.Sleep(100 * time.Millisecond) // consolidate cache.Set

				if val, xerr := cache.Get(ctx, cachesubnetRef); xerr == nil {
					casted, ok := val.(*Subnet)
					if ok {
						return casted, nil
					} else {
						logrus.WithContext(ctx).Warnf("wrong type of resources.Subnet")
					}
				} else {
					logrus.WithContext(ctx).Warnf("subnet cache response (%s): %v", cachesubnetRef, xerr)
				}
			}

			return subnetInstance, nil
		}()
		chRes <- result{ga, gerr}
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}
func LoadNetwork(inctx context.Context, svc iaas.Service, ref string) (resources.Network, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	lock, xerr := svc.GetLock(abstract.NetworkResource)
	if xerr != nil {
		return nil, xerr
	}

	lock.Lock()
	defer lock.Unlock()

	return loadNetwork(inctx, svc, ref)
}

// LoadNetwork loads the metadata of a subnet
func loadNetwork(inctx context.Context, svc iaas.Service, ref string) (resources.Network, fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  resources.Network
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		ga, gerr := func() (_ resources.Network, ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			if svc == nil {
				return nil, fail.InvalidParameterError("svc", "cannot be null value")
			}
			if ref = strings.TrimSpace(ref); ref == "" {
				return nil, fail.InvalidParameterError("ref", "cannot be empty string")
			}

			// trick to avoid collisions
			var kt *Network
			cacheref := fmt.Sprintf("%T/%s", kt, ref)

			cache, xerr := svc.GetCache(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				if val, xerr := cache.Get(ctx, cacheref); xerr == nil {
					casted, ok := val.(resources.Network)
					if ok {
						return casted, nil
					}
				}
			}

			cacheMissLoader := func() (data.Identifiable, fail.Error) { return onNetworkCacheMiss(ctx, svc, ref) }
			anon, xerr := cacheMissLoader()
			if xerr != nil {
				return nil, xerr
			}

			networkInstance, ok := anon.(resources.Network)
			if !ok {
				return nil, fail.InconsistentError("cache content should be a resources.Network", ref)
			}
			if networkInstance == nil {
				return nil, fail.InconsistentError("nil value found in Network cache for key '%s'", ref)
			}

			// if cache failed we are here, so we better retrieve updated information...
			xerr = networkInstance.Reload(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				err := cache.Set(ctx, fmt.Sprintf("%T/%s", kt, networkInstance.GetName()), networkInstance, &store.Options{Expiration: 120 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				time.Sleep(50 * time.Millisecond) // consolidate cache.Set
				hid, err := networkInstance.GetID()
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				err = cache.Set(ctx, fmt.Sprintf("%T/%s", kt, hid), networkInstance, &store.Options{Expiration: 120 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				time.Sleep(50 * time.Millisecond) // consolidate cache.Set

				if val, xerr := cache.Get(ctx, cacheref); xerr == nil {
					casted, ok := val.(resources.Network)
					if ok {
						return casted, nil
					} else {
						logrus.WithContext(ctx).Warnf("wrong type of resources.Network")
					}
				} else {
					logrus.WithContext(ctx).Warnf("network cache response (%s): %v", cacheref, xerr)
				}
			}

			return networkInstance, nil

		}()
		chRes <- result{ga, gerr}
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}
func LoadVolume(inctx context.Context, svc iaas.Service, ref string) (resources.Volume, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	lock, xerr := svc.GetLock(abstract.VolumeResource)
	if xerr != nil {
		return nil, xerr
	}

	lock.Lock()
	defer lock.Unlock()

	return loadVolume(inctx, svc, ref)
}

// LoadVolume loads the metadata of a subnet
func loadVolume(inctx context.Context, svc iaas.Service, ref string) (resources.Volume, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}
	if ref = strings.TrimSpace(ref); ref == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  resources.Volume
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		ga, gerr := func() (_ resources.Volume, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			// trick to avoid collisions
			var kt *volume
			cacheref := fmt.Sprintf("%T/%s", kt, ref)

			cache, xerr := svc.GetCache(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				if val, xerr := cache.Get(ctx, cacheref); xerr == nil {
					casted, ok := val.(resources.Volume)
					if ok {
						return casted, nil
					}
				}
			}

			cacheMissLoader := func() (data.Identifiable, fail.Error) { return onVolumeCacheMiss(ctx, svc, ref) }
			anon, xerr := cacheMissLoader()
			if xerr != nil {
				return nil, xerr
			}

			var ok bool
			volumeInstance, ok := anon.(resources.Volume)
			if !ok {
				return nil, fail.InconsistentError("value in cache for Volume with key '%s' is not a resources.Volume", ref)
			}
			if volumeInstance == nil {
				return nil, fail.InconsistentError("nil value in cache for Volume with key '%s'", ref)
			}

			// if cache failed we are here, so we better retrieve updated information...
			xerr = volumeInstance.Reload(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				err := cache.Set(ctx, fmt.Sprintf("%T/%s", kt, volumeInstance.GetName()), volumeInstance, &store.Options{Expiration: 120 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				time.Sleep(50 * time.Millisecond) // consolidate cache.Set
				hid, err := volumeInstance.GetID()
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				err = cache.Set(ctx, fmt.Sprintf("%T/%s", kt, hid), volumeInstance, &store.Options{Expiration: 120 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				time.Sleep(50 * time.Millisecond) // consolidate cache.Set

				if val, xerr := cache.Get(ctx, cacheref); xerr == nil {
					casted, ok := val.(resources.Volume)
					if ok {
						return casted, nil
					} else {
						logrus.WithContext(ctx).Warnf("wrong type of resources.Volume")
					}
				} else {
					logrus.WithContext(ctx).Warnf("volume cache response (%s): %v", cacheref, xerr)
				}
			}

			return volumeInstance, nil
		}()
		chRes <- result{ga, gerr}
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

func LoadShare(inctx context.Context, svc iaas.Service, ref string) (resources.Share, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	lock, xerr := svc.GetLock(abstract.ShareResource)
	if xerr != nil {
		return nil, xerr
	}

	lock.Lock()
	defer lock.Unlock()

	return loadShare(inctx, svc, ref)
}

// LoadShare returns the name of the host owing the Share 'ref', read from Object Storage
// logic: try to read until success.
//
//	If error is fail.ErrNotFound return this error
//	In case of any other error, abort the retry to propagate the error
//	If retry times out, return fail.ErrTimeout
func loadShare(inctx context.Context, svc iaas.Service, ref string) (resources.Share, fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  resources.Share
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		ga, gerr := func() (_ resources.Share, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			if svc == nil {
				return nil, fail.InvalidParameterCannotBeNilError("svc")
			}
			if ref == "" {
				return nil, fail.InvalidParameterError("ref", "cannot be empty string")
			}

			// trick to avoid collisions
			var kt *Share
			cacheref := fmt.Sprintf("%T/%s", kt, ref)

			cache, xerr := svc.GetCache(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				if val, xerr := cache.Get(ctx, cacheref); xerr == nil {
					casted, ok := val.(resources.Share)
					if ok {
						return casted, nil
					}
				}
			}

			cacheMissLoader := func() (data.Identifiable, fail.Error) { return onShareCacheMiss(ctx, svc, ref) }
			anon, xerr := cacheMissLoader()
			if xerr != nil {
				return nil, xerr
			}

			var ok bool
			var shareInstance resources.Share
			if shareInstance, ok = anon.(resources.Share); !ok {
				return nil, fail.InconsistentError("cache content should be a resources.Share", ref)
			}
			if shareInstance == nil {
				return nil, fail.InconsistentError("nil value found in Share cache for key '%s'", ref)
			}

			// if cache failed we are here, so we better retrieve updated information...
			xerr = shareInstance.Reload(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				err := cache.Set(ctx, fmt.Sprintf("%T/%s", kt, shareInstance.GetName()), shareInstance, &store.Options{Expiration: 120 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				time.Sleep(50 * time.Millisecond) // consolidate cache.Set
				hid, err := shareInstance.GetID()
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				err = cache.Set(ctx, fmt.Sprintf("%T/%s", kt, hid), shareInstance, &store.Options{Expiration: 120 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				time.Sleep(50 * time.Millisecond) // consolidate cache.Set

				if val, xerr := cache.Get(ctx, cacheref); xerr == nil {
					casted, ok := val.(resources.Share)
					if ok {
						return casted, nil
					} else {
						logrus.WithContext(ctx).Warnf("wrong type of resources.Share")
					}
				} else {
					logrus.WithContext(ctx).Warnf("share cache response (%s): %v", cacheref, xerr)
				}
			}

			return shareInstance, nil
		}()
		chRes <- result{ga, gerr}
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

func LoadBucket(inctx context.Context, svc iaas.Service, ref string) (resources.Bucket, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	lock, xerr := svc.GetLock(abstract.ObjectStorageBucketResource)
	if xerr != nil {
		return nil, xerr
	}

	lock.Lock()
	defer lock.Unlock()

	return loadBucket(inctx, svc, ref)
}

// LoadBucket instantiates a bucket struct and fill it with Provider metadata of Object Storage ObjectStorageBucket
func loadBucket(inctx context.Context, svc iaas.Service, name string) (resources.Bucket, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  resources.Bucket
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gb, gerr := func() (_ resources.Bucket, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			// trick to avoid collisions
			var kt *bucket
			cachename := fmt.Sprintf("%T/%s", kt, name)

			cache, xerr := svc.GetCache(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				if val, xerr := cache.Get(ctx, cachename); xerr == nil {
					casted, ok := val.(resources.Bucket)
					if ok {
						return casted, nil
					}
				}
			}

			cacheMissLoader := func() (data.Identifiable, fail.Error) { return onBucketCacheMiss(ctx, svc, name) }
			anon, xerr := cacheMissLoader()
			if xerr != nil {
				return nil, xerr
			}

			b, ok := anon.(resources.Bucket)
			if !ok {
				return nil, fail.InconsistentError("cache content should be a resources.Bucket", name)
			}

			if b == nil {
				return nil, fail.InconsistentError("nil value found in Bucket cache for key '%s'", name)
			}

			// if cache failed we are here, so we better retrieve updated information...
			xerr = b.Reload(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				err := cache.Set(ctx, fmt.Sprintf("%T/%s", kt, b.GetName()), b, &store.Options{Expiration: 120 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				time.Sleep(50 * time.Millisecond) // consolidate cache.Set
				hid, err := b.GetID()
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				err = cache.Set(ctx, fmt.Sprintf("%T/%s", kt, hid), b, &store.Options{Expiration: 120 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				time.Sleep(50 * time.Millisecond) // consolidate cache.Set

				if val, xerr := cache.Get(ctx, cachename); xerr == nil {
					casted, ok := val.(resources.Bucket)
					if ok {
						return casted, nil
					} else {
						logrus.WithContext(ctx).Warnf("wrong type of resources.Bucket")
					}
				} else {
					logrus.WithContext(ctx).Warnf("bucket cache response (%s): %v", cachename, xerr)
				}
			}

			return b, nil
		}()
		chRes <- result{gb, gerr}
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

func LoadSecurityGroup(inctx context.Context, svc iaas.Service, ref string) (*SecurityGroup, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	lock, xerr := svc.GetLock(abstract.SecurityGroupResource)
	if xerr != nil {
		return nil, xerr
	}

	lock.Lock()
	defer lock.Unlock()

	return loadSecurityGroup(inctx, svc, ref)
}

// LoadSecurityGroup ...
func loadSecurityGroup(inctx context.Context, svc iaas.Service, ref string) (*SecurityGroup, fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  *SecurityGroup
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		ga, gerr := func() (_ *SecurityGroup, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			if svc == nil {
				return nil, fail.InvalidParameterError("svc", "cannot be nil")
			}
			if ref == "" {
				return nil, fail.InvalidParameterError("ref", "cannot be empty string")
			}

			// trick to avoid collisions
			var kt *SecurityGroup
			cacheref := fmt.Sprintf("%T/%s", kt, ref)

			cache, xerr := svc.GetCache(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				if val, xerr := cache.Get(ctx, cacheref); xerr == nil {
					casted, ok := val.(*SecurityGroup)
					if ok {
						return casted, nil
					}
				}
			}

			cacheMissLoader := func() (data.Identifiable, fail.Error) { return onSGCacheMiss(ctx, svc, ref) }
			anon, xerr := cacheMissLoader()
			if xerr != nil {
				return nil, xerr
			}

			var ok bool
			sgInstance, ok := anon.(*SecurityGroup)
			if !ok {
				return nil, fail.InconsistentError("cache content should be a *SecurityGroup", ref)
			}
			if sgInstance == nil {
				return nil, fail.InconsistentError("nil value found in Security Group cache for key '%s'", ref)
			}

			// if cache failed we are here, so we better retrieve updated information...
			xerr = sgInstance.Reload(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				err := cache.Set(ctx, fmt.Sprintf("%T/%s", kt, sgInstance.GetName()), sgInstance, &store.Options{Expiration: 120 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				time.Sleep(50 * time.Millisecond) // consolidate cache.Set
				hid, err := sgInstance.GetID()
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				err = cache.Set(ctx, fmt.Sprintf("%T/%s", kt, hid), sgInstance, &store.Options{Expiration: 120 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				time.Sleep(50 * time.Millisecond) // consolidate cache.Set

				if val, xerr := cache.Get(ctx, cacheref); xerr == nil {
					casted, ok := val.(*SecurityGroup)
					if ok {
						return casted, nil
					} else {
						logrus.WithContext(ctx).Warnf("wrong type of resources.SecurityGroup")
					}
				} else {
					logrus.WithContext(ctx).Warnf("sg cache response (%s): %v", cacheref, xerr)
				}
			}

			return sgInstance, nil
		}()
		chRes <- result{ga, gerr}
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}
