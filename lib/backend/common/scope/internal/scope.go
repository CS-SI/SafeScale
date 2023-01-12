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

package internal

import (
	"context"
	"path/filepath"
	"strings"
	"sync"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	terraformerapi "github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	hostfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/host"
	labelfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/label"
	networkfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/network"
	securitygroupfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/securitygroup"
	subnetfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/subnet"
	volumefactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/volume"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v2"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/puzpuzpuz/xsync"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/externals/consul/consumer"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/global"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

var (
	scopeList sync.Map
)

type (
	// providerUsingTerraform interface for use by scope
	providerUsingTerraform interface {
		ConsolidateNetworkSnippet(*abstract.Network) fail.Error             // configures if needed Terraform Snippet to use for abstract.Network in parameter
		ConsolidateSubnetSnippet(*abstract.Subnet) fail.Error               // configures if needed Terraform Snippet to use for abstract.Subnet in parameter
		ConsolidateSecurityGroupSnippet(*abstract.SecurityGroup) fail.Error // configures if needed Terraform Snippet to use for abstract.SecurityGroup in parameter
		ConsolidateHostSnippet(*abstract.HostCore) fail.Error               // configures if needed Terraform Snippet to use for abstract.Host in parameter
		// ConsolidateLabelSnippet(*abstract.Label) fail.Error                // configures if needed Terraform Snippet to use for abstract.Label in parameter
		ConsolidateVolumeSnippet(*abstract.Volume) fail.Error // configures if needed Terraform Snippet to use for abstract.Volume
	}

	// scope contains information about context of the Job
	scope struct {
		lock         *sync.RWMutex
		resources    *xsync.MapOf[string, terraformerapi.Resource]
		consulClient *consumer.Client
		consulKV     *consumer.KV
		service      iaasapi.Service
		organization string
		project      string
		tenant       string
		description  string
		kvPath       string
		fsPath       string
		loaded       bool
	}
)

// Load returns an existing scope from scope list
func Load(organization, project, tenant string) (*scope, fail.Error) {
	if organization == "" {
		organization = global.DefaultOrganization
	}
	if project == "" {
		project = global.DefaultProject
	}
	if tenant == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("tenant")
	}

	kvPath := buildKVPath(organization, project, tenant)
	entry, loaded := scopeList.Load(kvPath)
	if !loaded {
		return nil, fail.NotFoundError("failed to find a Scope identified by '%s'", kvPath)
	}

	out, ok := entry.(*scope)
	if !ok {
		return nil, fail.InconsistentError("loaded scope is not of type '*scope'")
	}

	return out, nil
}

// buildKVPath assembles the path that will be used as KV prefix
func buildKVPath(organization, project, tenant string) string {
	return strings.Join([]string{organization, project, tenant}, "/")
}

// New creates a new scope
func New(organization, project, tenant, description string) (*scope, fail.Error) {
	if organization == "" {
		organization = global.DefaultOrganization
	}
	if project == "" {
		project = global.DefaultProject
	}
	if tenant == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("tenant")
	}

	out := &scope{
		organization: organization,
		project:      project,
		tenant:       tenant,
		description:  description,
		fsPath:       filepath.Join(organization, project, tenant),
		kvPath:       strings.Join([]string{organization, project, tenant}, "/"),
		resources:    xsync.NewMapOf[terraformerapi.Resource](),
		lock:         &sync.RWMutex{},
	}

	_, loaded := scopeList.LoadOrStore(out.kvPath, out)
	if loaded {
		return nil, fail.DuplicateError("there is already a Scope '%s'", out.ID())
	}

	var xerr fail.Error
	out.consulClient, xerr = consumer.NewClient(consumer.WithAddress("localhost:" + global.Settings.Backend.Consul.HttpPort))
	if xerr != nil {
		return nil, xerr
	}

	out.consulKV, xerr = out.consulClient.NewKV(consumer.WithPrefix(out.kvPath), consumer.WithSessionName(out.kvPath))
	if xerr != nil {
		return nil, xerr
	}

	return out, nil
}

// IsNull tells if the scope is considered as null value
func (s *scope) IsNull() bool {
	return s == nil || s.organization == "" || s.project == "" || s.tenant == "" || s.resources == nil
}

// IsLoaded tells if resources of the scope have been browsed
func (s *scope) IsLoaded() bool {
	if s.IsNull() {
		return false
	}

	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.loaded
}

func (s *scope) String() string {
	if valid.IsNull(s) {
		return "unknown"
	}

	return s.kvPath
}

// ID returns the scope identifier (which is equal to KVPath())
func (s *scope) ID() string {
	if s.IsNull() {
		return ""
	}

	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.kvPath
}

// Organization returns the organization of the scope
func (s *scope) Organization() string {
	if s.IsNull() {
		return ""
	}

	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.organization
}

// Project returns the project of the scope
func (s *scope) Project() string {
	if s.IsNull() {
		return ""
	}

	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.project
}

// Tenant returns the tenant of the scope
func (s *scope) Tenant() string {
	if s.IsNull() {
		return ""
	}

	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.tenant
}

// Description returns the description of the scope
func (s *scope) Description() string {
	if s.IsNull() {
		return ""
	}

	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.description
}

// KVPath returns the prefix path of the scope in K/V store
func (s *scope) KVPath() string {
	if s.IsNull() {
		return ""
	}

	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.kvPath
}

// FSPath returns the prefix path of the scope for FS use
func (s *scope) FSPath() string {
	if s.IsNull() {
		return ""
	}

	return s.fsPath
}

func (s *scope) Service() iaasapi.Service {
	if s.IsNull() {
		return nil
	}

	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.service
}

func (s *scope) ConsulKV() *consumer.KV {
	if valid.IsNull(s) {
		return nil
	}

	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.consulKV
}

func (s *scope) LoadAbstracts(ctx context.Context) fail.Error {
	if valid.IsNull(s) {
		return fail.InvalidInstanceError()
	}

	provider, xerr := s.extractProvider(ctx)
	if xerr != nil {
		return xerr
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	if s.loaded {
		return nil
	}

	xerr = s.loadNetworks(ctx, provider)
	if xerr != nil {
		return xerr
	}

	xerr = s.loadSubnets(ctx, provider)
	if xerr != nil {
		return xerr
	}

	xerr = s.loadSecurityGroups(ctx, provider)
	if xerr != nil {
		return xerr
	}

	xerr = s.loadLabels(ctx, provider)
	if xerr != nil {
		return xerr
	}

	xerr = s.loadHosts(ctx, provider)
	if xerr != nil {
		return xerr
	}

	xerr = s.loadVolumes(ctx, provider)
	if xerr != nil {
		return xerr
	}

	// VPL: disabled for now as it's not currently evident we need to load these abstracts for terraform
	// xerr = s.loadClusters(ctx, provider)
	// if xerr != nil {
	// 	return xerr
	// }
	//
	// xerr = s.loadBuckets(ctx, provider)
	// if xerr != nil {
	// 	return xerr
	// }

	s.loaded = true
	return nil
}

func (s *scope) loadNetworks(ctx context.Context, provider providerUsingTerraform) (ferr fail.Error) {
	count := 0
	defer s.loadLogHelper("Networks", &ferr, &count)()

	browser, xerr := networkfactory.New(ctx)
	if xerr != nil {
		return xerr
	}

	return browser.Browse(ctx, func(an *abstract.Network) fail.Error {
		innerXErr := provider.ConsolidateNetworkSnippet(an)
		if innerXErr != nil {
			return innerXErr
		}

		innerXErr = s.registerResource(an)
		if innerXErr != nil {
			return innerXErr
		}

		count++
		return nil
	})
}

func (s *scope) loadLogHelper(kind string, xerr *fail.Error, count *int) func() {
	logrus.Debugf("Loading existing %s in Scope '%s'...", kind, s.String())
	return func() {
		if xerr != nil && *xerr != nil {
			logrus.Errorf("Failed to load existing %s in Scope '%s': %s", kind, s.String(), (*xerr).Error())
		} else {
			if *count > 0 {
				logrus.Debugf("Successfully loaded %d existing %s in Scope '%s'", *count, kind, s.String())
			} else {
				logrus.Debugf("No existing %s found", kind)
			}
		}
	}
}

func (s *scope) extractProvider(ctx context.Context) (providerUsingTerraform, fail.Error) {
	myjob, xerr := jobapi.FromContext(ctx)
	if xerr != nil {
		return nil, xerr
	}

	provider, xerr := myjob.Service().ProviderDriver()
	if xerr != nil {
		return nil, xerr
	}

	providerSuperset, ok := provider.(providerUsingTerraform)
	if !ok {
		return nil, fail.InconsistentError("failed to cast provodier to 'providerUsingTerraform'")
	}

	return providerSuperset, nil
}

func (s *scope) loadSubnets(ctx context.Context, provider providerUsingTerraform) (ferr fail.Error) {
	count := 0
	defer s.loadLogHelper("Subnets", &ferr, &count)()

	browser, xerr := subnetfactory.New(ctx)
	if xerr != nil {
		return xerr
	}

	return browser.Browse(ctx, func(as *abstract.Subnet) fail.Error {
		innerXErr := provider.ConsolidateSubnetSnippet(as)
		if innerXErr != nil {
			return innerXErr
		}

		innerXErr = s.registerResource(as)
		if innerXErr != nil {
			return innerXErr
		}

		count++
		return nil
	})
}

func (s *scope) loadSecurityGroups(ctx context.Context, provider providerUsingTerraform) (ferr fail.Error) {
	count := 0
	defer s.loadLogHelper("Security Groups", &ferr, &count)()

	browser, xerr := securitygroupfactory.New(ctx)
	if xerr != nil {
		return xerr
	}

	return browser.Browse(ctx, func(asg *abstract.SecurityGroup) fail.Error {
		innerXErr := provider.ConsolidateSecurityGroupSnippet(asg)
		if innerXErr != nil {
			return innerXErr
		}

		innerXErr = s.registerResource(asg)
		if innerXErr != nil {
			return innerXErr
		}

		count++
		return nil
	})
}

func (s *scope) loadHosts(ctx context.Context, provider providerUsingTerraform) (ferr fail.Error) {
	count := 0
	defer s.loadLogHelper("Hosts", &ferr, &count)()

	browser, xerr := hostfactory.New(ctx)
	if xerr != nil {
		return xerr
	}

	svc := browser.Service()

	return browser.Browse(ctx, func(ahc *abstract.HostCore) fail.Error {
		innerXErr := provider.ConsolidateHostSnippet(ahc)
		if innerXErr != nil {
			return innerXErr
		}

		ahf, innerXErr := svc.InspectHost(ctx, ahc)
		if innerXErr != nil {
			return innerXErr
		}

		// -- Need to add bound Security Groups of the Host as Extra data to abstract.HostFull
		host, innerXErr := hostfactory.Load(ctx, ahc.ID)
		if innerXErr != nil {
			return innerXErr
		}

		innerXErr = host.Inspect(ctx, func(_ clonable.Clonable, props *serialize.JSONProperties) fail.Error {
			inspectXErr := props.Inspect(hostproperty.NetworkV2, func(p clonable.Clonable) fail.Error {
				networkV2, inspectErr := clonable.Cast[*propertiesv2.HostNetworking](p)
				if inspectErr != nil {
					return fail.Wrap(inspectErr)
				}

				subnetList := make([]*abstract.Subnet, 0, len(networkV2.SubnetsByName))
				for k := range networkV2.SubnetsByName {
					entry, found := s.resources.Load("subnet:" + k)
					if !found {
						logrus.WithContext(ctx).Errorf("inconsistency detected in metadata: Host '%s' is bound to Subnet '%s', which does not exist", ahc.Name, k)
						continue
					}

					casted, inspectErr := lang.Cast[*abstract.Subnet](entry)
					if inspectErr != nil {
						return fail.Wrap(inspectErr)
					}

					cloned, inspectErr := clonable.CastedClone[*abstract.Subnet](casted)
					if inspectErr != nil {
						return fail.Wrap(inspectErr)
					}

					subnetList = append(subnetList, cloned)
				}
				return ahf.AddOptions(abstract.WithExtraData("SecurityGroupByID", subnetList))
			})
			if inspectXErr != nil {
				return inspectXErr
			}

			return props.Inspect(hostproperty.SecurityGroupsV1, func(p clonable.Clonable) fail.Error {
				sgsV1, innerErr := clonable.Cast[*propertiesv1.HostSecurityGroups](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				list := make(map[string]string, len(sgsV1.ByName))
				for k, v := range sgsV1.ByName {
					list[v] = k
				}
				return ahf.AddOptions(abstract.WithExtraData("SecurityGroupByID", list))
			})
		})

		// -- register resource in scope
		innerXErr = s.registerResource(ahf)
		if innerXErr != nil {
			return innerXErr
		}

		count++
		return nil
	})
}

func (s *scope) loadLabels(ctx context.Context, _ providerUsingTerraform) (ferr fail.Error) {
	count := 0
	defer s.loadLogHelper("Labels", &ferr, &count)()

	browser, xerr := labelfactory.New(ctx)
	if xerr != nil {
		return xerr
	}

	return browser.Browse(ctx, func(al *abstract.Label) fail.Error {
		// provider.ConsolidateLabelSnippet(al)
		innerXErr := s.registerResource(al)
		if innerXErr != nil {
			return innerXErr
		}

		count++
		return nil
	})
}

func (s *scope) loadVolumes(ctx context.Context, provider providerUsingTerraform) (ferr fail.Error) {
	count := 0
	defer s.loadLogHelper("Volumes", &ferr, &count)()

	browser, xerr := volumefactory.New(ctx)
	if xerr != nil {
		return xerr
	}

	return browser.Browse(ctx, func(av *abstract.Volume) fail.Error {
		innerXErr := provider.ConsolidateVolumeSnippet(av)
		if innerXErr != nil {
			return innerXErr
		}

		innerXErr = s.registerResource(av)
		if innerXErr != nil {
			return innerXErr
		}

		count++
		return nil
	})
}

// VPL: not sure we need to keep these abstracts right now...
// func (s *scope) loadClusters(ctx context.Context) (ferr fail.Error) {
// 	count := 0
// 	defer s.loadLogHelper("Clusters", &ferr, &count)()
//
// 	browser, xerr := clusterfactory.New(ctx)
// 	if xerr != nil {
// 		return xerr
// 	}
//
// 	return browser.Browse(ctx, func(ac *abstract.Cluster) fail.Error {
// 		innerXErr := s.registerResource(ac)
// 		if innerXErr != nil {
// 			return innerXErr
// 		}
//
// 		count++
// 		return nil
// 	})
// }
//
// func (s *scope) loadBuckets(ctx context.Context) (ferr fail.Error) {
// 	count := 0
// 	defer s.loadLogHelper("Buckets", &ferr, &count)()
//
// 	browser, xerr := bucketfactory.New(ctx)
// 	if xerr != nil {
// 		return xerr
// 	}
//
// 	return browser.Browse(ctx, func(ab *abstract.Bucket) fail.Error {
// 		innerXErr := s.registerResource(ab)
// 		if innerXErr != nil {
// 			return innerXErr
// 		}
//
// 		count++
// 		return nil
// 	})
// }

// AllResources returns all abstracts registered in Scope
func (s *scope) AllResources() (map[string]terraformerapi.Resource, fail.Error) {
	if valid.IsNull(s) {
		return nil, fail.InvalidInstanceError()
	}

	s.lock.RLock()
	defer s.lock.RUnlock()

	list := make(map[string]terraformerapi.Resource, s.resources.Size())
	s.resources.Range(func(key string, value terraformerapi.Resource) bool {
		list[key] = value
		return true
	})

	return list, nil
}

// Resource returns the resource with kind and name
func (s *scope) Resource(kind, name string) (terraformerapi.Resource, fail.Error) {
	if valid.IsNull(s) {
		return nil, fail.InvalidInstanceError()
	}
	if kind == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("kind")
	}
	if name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	s.lock.RLock()
	defer s.lock.RUnlock()

	queryName := kind + ":" + name
	entry, found := s.resources.Load(queryName)
	if !found {
		return nil, fail.NotFoundError("failed to find %s resource '%s' in Scope", kind, name)
	}

	value, ok := entry.(clonable.Clonable)
	if !ok {
		return nil, fail.InconsistentError("failed to cast resource to 'clonable.Clonable'")
	}

	cloned, err := clonable.CastedClone[terraformerapi.Resource](value)
	if err != nil {
		return nil, fail.Wrap(err)
	}

	return cloned, nil
}

// RegisterResource ...
func (s *scope) RegisterResource(rsc terraformerapi.Resource) fail.Error {
	if valid.IsNull(s) {
		return fail.InvalidInstanceError()
	}
	if valid.IsNull(rsc) {
		return fail.InvalidParameterCannotBeNilError("rsc")
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	return s.registerResource(rsc)
}

// registerResource ...
func (s *scope) registerResource(rsc terraformerapi.Resource) fail.Error {
	kind, name, queryName, xerr := s.extractResourceIndex(rsc)
	if xerr != nil {
		return xerr
	}

	// Check duplicate by name
	_, found := s.resources.Load(queryName)
	if found {
		return fail.DuplicateError("a %s named '%s' is already registered", kind, name)
	}

	// Now registers resource
	s.resources.Store(queryName, rsc)
	return nil
}

// ReplaceResource does replace a resource already there, or register it if not present
func (s *scope) ReplaceResource(rsc terraformerapi.Resource) fail.Error {
	_, _, queryName, xerr := s.extractResourceIndex(rsc)
	if xerr != nil {
		return xerr
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	s.resources.Store(queryName, rsc)
	return nil
}

// UnregisterResource unregisters a resource from Scope
func (s *scope) UnregisterResource(rsc terraformerapi.Resource) fail.Error {
	if valid.IsNull(s) {
		return fail.InvalidInstanceError()
	}
	if valid.IsNull(rsc) {
		return fail.InvalidParameterCannotBeNilError("rsc")
	}

	_, _, queryName, xerr := s.extractResourceIndex(rsc)
	if xerr != nil {
		return xerr
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	s.resources.Delete(queryName)
	return nil
}

// extractResourceIndex returns kind, name and index corresponding to resource
func (s *scope) extractResourceIndex(rsc terraformerapi.Resource) (string, string, string, fail.Error) {
	if valid.IsNull(s) {
		return "", "", "", fail.InvalidInstanceError()
	}
	if valid.IsNull(rsc) {
		return "", "", "", fail.InvalidParameterCannotBeNilError("rsc")
	}

	return rsc.Kind(), rsc.GetName(), rsc.UniqueID(), nil
}
