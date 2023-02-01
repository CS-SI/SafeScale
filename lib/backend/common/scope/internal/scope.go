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

package internal

import (
	"context"
	"path/filepath"
	"strings"
	"sync"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	hostfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/host"
	labelfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/label"
	networkfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/network"
	securitygroupfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/securitygroup"
	subnetfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/subnet"
	volumefactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/volume"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
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
		abstractsByID   *xsync.MapOf[string, abstract.Abstract]
		abstractsByName *xsync.MapOf[string, abstract.Abstract]
		mu              *sync.Mutex
		consulClient    *consumer.Client
		consulKV        *consumer.KV
		service         iaasapi.Service
		organization    string
		project         string
		tenant          string
		description     string
		kvPath          string
		fsPath          string
		loaded          bool
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

	out, err := lang.Cast[*scope](entry)
	if err != nil {
		return nil, fail.Wrap(err)
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
		organization:    organization,
		project:         project,
		tenant:          tenant,
		description:     description,
		fsPath:          filepath.Join(organization, project, tenant),
		kvPath:          strings.Join([]string{organization, project, tenant}, "/"),
		abstractsByID:   xsync.NewMapOf[abstract.Abstract](),
		abstractsByName: xsync.NewMapOf[abstract.Abstract](),
		mu:              &sync.Mutex{},
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
	return s == nil || s.organization == "" || s.project == "" || s.tenant == "" || s.abstractsByID == nil || s.abstractsByName == nil
}

// IsLoaded tells if resources of the scope have been browsed
func (s *scope) IsLoaded() bool {
	if s.IsNull() {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.loaded
}

func (s *scope) String() string {
	if valid.IsNull(s) {
		return "unknown"
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.kvPath
}

// ID returns the scope identifier (which is equal to KVPath())
func (s *scope) ID() string {
	if s.IsNull() {
		return ""
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.kvPath
}

// Organization returns the organization of the scope
func (s *scope) Organization() string {
	if s.IsNull() {
		return ""
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.organization
}

// Project returns the project of the scope
func (s *scope) Project() string {
	if s.IsNull() {
		return ""
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.project
}

// Tenant returns the tenant of the scope
func (s *scope) Tenant() string {
	if s.IsNull() {
		return ""
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.tenant
}

// Description returns the description of the scope
func (s *scope) Description() string {
	if s.IsNull() {
		return ""
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.description
}

// KVPath returns the prefix path of the scope in K/V store
func (s *scope) KVPath() string {
	if s.IsNull() {
		return ""
	}

	s.mu.Lock()
	defer s.mu.Unlock()

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

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.service
}

// ConsulKV returns the instance of lib.externals.consul.consumer.KV to access consul Key/Value store
func (s *scope) ConsulKV() *consumer.KV {
	if valid.IsNull(s) {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.consulKV
}

// LoadAbstracts loads the existing abstracts when Scope is instanciated by jobmanager
func (s *scope) LoadAbstracts(ctx context.Context) fail.Error {
	if valid.IsNull(s) {
		return fail.InvalidInstanceError()
	}

	provider, xerr := s.extractProvider(ctx)
	if xerr != nil {
		return xerr
	}

	s.mu.Lock()
	loaded := s.loaded
	s.mu.Unlock()
	if loaded {
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

		innerXErr = s.registerAbstract(an)
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

		innerXErr = s.registerAbstract(as)
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

		innerXErr = s.RegisterAbstract(asg)
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

	// svc := browser.Service()

	return browser.Browse(ctx, func(ahc *abstract.HostCore) (ferr fail.Error) {
		innerXErr := provider.ConsolidateHostSnippet(ahc)
		if innerXErr != nil {
			return innerXErr
		}

		// Need to add bound Security Groups and Subnets of the Host as Extra data to abstract.HostFull; done using Host Factory Load call
		_, innerXErr = hostfactory.Load(ctx, ahc.ID)
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
		innerXErr := s.RegisterAbstract(al)
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

		innerXErr = s.RegisterAbstract(av)
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
// 		innerXErr := s.registerAbstract(ac)
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
// 		innerXErr := s.registerAbstract(ab)
// 		if innerXErr != nil {
// 			return innerXErr
// 		}
//
// 		count++
// 		return nil
// 	})
// }

// AllAbstracts returns all abstracts registered in Scope
func (s *scope) AllAbstracts() (map[string]abstract.Abstract, fail.Error) {
	if valid.IsNull(s) {
		return nil, fail.InvalidInstanceError()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	list := make(map[string]abstract.Abstract, s.abstractsByID.Size())
	s.abstractsByName.Range(func(key string, value abstract.Abstract) bool {
		list[key] = value
		return true
	})

	return list, nil
}

// AbstractByName returns the resource with kind and name
func (s *scope) AbstractByName(kind, name string) (abstract.Abstract, fail.Error) {
	if valid.IsNull(s) {
		return nil, fail.InvalidInstanceError()
	}
	if kind == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("kind")
	}
	if name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	queryName := kind + ":" + name
	entry, found := s.abstractsByName.Load(queryName)
	if !found {
		return nil, fail.NotFoundError("failed to find %s resource '%s' in Scope", kind, name)
	}

	value, ok := entry.(clonable.Clonable)
	if !ok {
		return nil, fail.InconsistentError("failed to cast resource to 'clonable.Clonable'")
	}

	cloned, err := clonable.CastedClone[abstract.Abstract](value)
	if err != nil {
		return nil, fail.Wrap(err)
	}

	return cloned, nil
}

// AbstractByID returns the resource with kind and id
func (s *scope) AbstractByID(kind, id string) (abstract.Abstract, fail.Error) {
	if valid.IsNull(s) {
		return nil, fail.InvalidInstanceError()
	}
	if kind == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("kind")
	}
	if id == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	queryName := kind + ":" + id
	entry, found := s.abstractsByID.Load(queryName)
	if !found {
		return nil, fail.NotFoundError("failed to find %s abstract with ID '%s' in Scope", kind, id)
	}

	value, ok := entry.(clonable.Clonable)
	if !ok {
		return nil, fail.InconsistentError("failed to cast resource to 'clonable.Clonable'")
	}

	cloned, err := clonable.CastedClone[abstract.Abstract](value)
	if err != nil {
		return nil, fail.Wrap(err)
	}

	return cloned, nil
}

// RegisterAbstract ...
func (s *scope) RegisterAbstract(rsc abstract.Abstract) fail.Error {
	if valid.IsNull(s) {
		return fail.InvalidInstanceError()
	}
	if valid.IsNull(rsc) {
		return fail.InvalidParameterCannotBeNilError("rsc")
	}

	return s.registerAbstract(rsc)
}

// RegisterAbstractIfNeeded ...
func (s *scope) RegisterAbstractIfNeeded(rsc abstract.Abstract) (bool, fail.Error) {
	if valid.IsNull(s) {
		return false, fail.InvalidInstanceError()
	}
	if valid.IsNull(rsc) {
		return false, fail.InvalidParameterCannotBeNilError("rsc")
	}

	xerr := s.registerAbstract(rsc)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrDuplicate:
			// If duplicate, do nothing and do not generate an error
			return false, nil
		default:
			return false, xerr
		}
	}

	return true, nil
}

// registerAbstract ...
func (s *scope) registerAbstract(rsc abstract.Abstract) fail.Error {
	kind, name, id, queryByName, queryByID, xerr := s.extractAbstractIndexes(rsc)
	if xerr != nil {
		return xerr
	}

	// Check duplicate by name
	_, found := s.abstractsByName.Load(queryByName)
	if found {
		return fail.DuplicateError("a %s with name '%s' is already registered", kind, name)
	}

	_, found = s.abstractsByID.Load(queryByID)
	if found {
		return fail.DuplicateError("a %s with ID '%s' is already registered", kind, id)
	}

	// Now registers abstract
	s.abstractsByName.Store(queryByName, rsc)
	s.abstractsByID.Store(queryByID, rsc)
	return nil
}

// // ReplaceAbstract does replace a resource already there, or register it if not present
// func (s *scope) ReplaceAbstract(rsc abstract.Abstract) fail.Error {
// 	kind, _, _, queryByName, queryByID, xerr := s.extractAbstractIndexes(rsc)
// 	if xerr != nil {
// 		return xerr
// 	}
// 	_ = kind
//
// 	s.abstractsByName.Store(queryByName, rsc)
// 	s.abstractsByID.Store(queryByID, rsc)
// 	return nil
// }

// UnregisterAbstract unregisters a resource from Scope
func (s *scope) UnregisterAbstract(rsc abstract.Abstract) fail.Error {
	if valid.IsNull(s) {
		return fail.InvalidInstanceError()
	}
	if valid.IsNull(rsc) {
		return fail.InvalidParameterCannotBeNilError("rsc")
	}

	_, _, _, queryByName, queryByID, xerr := s.extractAbstractIndexes(rsc)
	if xerr != nil {
		return xerr
	}

	s.abstractsByName.Delete(queryByName)
	s.abstractsByID.Delete(queryByID)
	return nil
}

// extractAbstractIndexes extract some information from abstract
// returns:
// - kind: the kind of abstract
// - name: the name of abstract
// - id: the id of abstract
// - indexByName: the index used to find abstract by name in Scope
// - indexByID: the index used to find abstract by id in Scope
// - error: if error occurs, none of the returned values are pertinent
func (s *scope) extractAbstractIndexes(rsc abstract.Abstract) (kind, name, id, indexByName, indexByID string, ferr fail.Error) {
	if valid.IsNull(s) {
		return "", "", "", "", "", fail.InvalidInstanceError()
	}
	if valid.IsNull(rsc) {
		return "", "", "", "", "", fail.InvalidParameterCannotBeNilError("rsc")
	}

	id, err := rsc.GetID()
	if err != nil {
		return "", "", "", "", "", fail.Wrap(err)
	}

	return rsc.Kind(), rsc.GetName(), id, rsc.Kind() + ":" + rsc.GetName(), rsc.Kind() + ":" + id, nil
}
