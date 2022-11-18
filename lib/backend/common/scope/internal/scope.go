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
	hostfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/host"
	labelfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/label"
	networkfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/network"
	securitygroupfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/securitygroup"
	subnetfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/subnet"
	volumefactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/volume"
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
		ConsolidateNetworkSnippet(*abstract.Network)             // configures if needed Terraform Snippet to use for abstract.Network in parameter
		ConsolidateSubnetSnippet(*abstract.Subnet)               // configures if needed Terraform Snippet to use for abstract.Subnet in parameter
		ConsolidateSecurityGroupSnippet(*abstract.SecurityGroup) // configures if needed Terraform Snippet to use for abstract.SecurityGroup in parameter
		ConsolidateHostSnippet(*abstract.HostCore)               // configures if needed Terraform Snippet to use for abstract.Host in parameter
		// ConsolidateLabelSnippet(*abstract.Label)                 // configures if needed Terraform Snippet to use for abstract.Label in parameter
		ConsolidateVolumeSnippet(*abstract.Volume) // configures if needed Terraform Snippet to use for abstract.Volume
	}

	// scope contains information about context of the Job
	scope struct {
		lock           *sync.RWMutex
		resourceByName *xsync.MapOf[string, string]
		resourceByID   *xsync.MapOf[string, terraformerapi.Resource]
		consulClient   *consumer.Client
		consulKV       *consumer.KV
		service        iaasapi.Service
		organization   string
		project        string
		tenant         string
		description    string
		kvPath         string
		fsPath         string
		loaded         bool
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
		organization:   organization,
		project:        project,
		tenant:         tenant,
		description:    description,
		fsPath:         filepath.Join(organization, project, tenant),
		kvPath:         strings.Join([]string{organization, project, tenant}, "/"),
		resourceByID:   xsync.NewMapOf[terraformerapi.Resource](),
		resourceByName: xsync.NewMapOf[string](),
		lock:           &sync.RWMutex{},
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
	return s == nil || s.organization == "" || s.project == "" || s.tenant == "" || s.resourceByName == nil || s.resourceByID == nil
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

// // Resource returns the resource corresponding to key (being an id or a name)
// func (s *scope) Resource(kind string, ref string) (clonable.Clonable, fail.Error) {
// 	if valid.IsNull(s) {
// 		return nil, fail.InvalidInstanceError()
// 	}
// 	if ref = strings.TrimSpace(ref); ref == "" {
// 		return nil, fail.InvalidParameterCannotBeEmptyStringError("ref")
// 	}
//
// 	index := kind + ":" + ref
// 	id, found := s.resourceByName.Load(ref)
// 	if found {
// 		index = kind + ":" + id
// 	}
//
// 	rsc, found := s.resourceByID.Load(index)
// 	if found {
// 		return rsc, nil
// 	}
//
// 	return nil, fail.NotFoundError("failed to find resource identified by %s", ref)
// }

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
		provider.ConsolidateNetworkSnippet(an)
		casted, innerErr := lang.Cast[terraformerapi.Resource](an)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		innerXErr := s.unsafeRegisterResource(casted)
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

	providerSuperset, err := lang.Cast[providerUsingTerraform](provider)
	if err != nil {
		return nil, fail.Wrap(err)
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
		provider.ConsolidateSubnetSnippet(as)
		casted, innerErr := lang.Cast[terraformerapi.Resource](as)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		innerXErr := s.unsafeRegisterResource(casted)
		if innerXErr != nil {
			return innerXErr
		}

		count++
		return nil
	})
}

func (s *scope) loadSecurityGroups(ctx context.Context, provider providerUsingTerraform) (ferr fail.Error) {
	count := 0
	defer s.loadLogHelper("Hosts", &ferr, &count)()

	browser, xerr := securitygroupfactory.New(ctx)
	if xerr != nil {
		return xerr
	}

	return browser.Browse(ctx, func(asg *abstract.SecurityGroup) fail.Error {
		provider.ConsolidateSecurityGroupSnippet(asg)
		casted, innerErr := lang.Cast[terraformerapi.Resource](asg)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		innerXErr := s.unsafeRegisterResource(casted)
		if innerXErr != nil {
			return innerXErr
		}

		count++
		return nil
	})
}

func (s *scope) loadHosts(ctx context.Context, provider providerUsingTerraform) (ferr fail.Error) {
	count := 0
	defer s.loadLogHelper("Networks", &ferr, &count)()

	browser, xerr := hostfactory.New(ctx)
	if xerr != nil {
		return xerr
	}

	return browser.Browse(ctx, func(ahc *abstract.HostCore) fail.Error {
		provider.ConsolidateHostSnippet(ahc)
		casted, innerErr := lang.Cast[terraformerapi.Resource](ahc)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		innerXErr := s.unsafeRegisterResource(casted)
		if innerXErr != nil {
			return innerXErr
		}

		count++
		return nil
	})
}

func (s *scope) loadLabels(ctx context.Context, provider providerUsingTerraform) (ferr fail.Error) {
	count := 0
	defer s.loadLogHelper("Labels", &ferr, &count)()

	browser, xerr := labelfactory.New(ctx)
	if xerr != nil {
		return xerr
	}

	return browser.Browse(ctx, func(al *abstract.Label) fail.Error {
		// provider.ConsolidateLabelSnippet(al)
		casted, innerErr := lang.Cast[terraformerapi.Resource](al)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		innerXErr := s.unsafeRegisterResource(casted)
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
		provider.ConsolidateVolumeSnippet(av)
		casted, innerErr := lang.Cast[terraformerapi.Resource](av)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		innerXErr := s.unsafeRegisterResource(casted)
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
// 		casted, innerErr := lang.Cast[terraformerapi.Resource](ac)
// 		if innerErr != nil {
// 			return fail.Wrap(innerErr)
// 		}
//
// 		innerXErr := s.unsafeRegisterResource(casted)
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
// 		casted, innerErr := lang.Cast[terraformerapi.Resource](ab)
// 		if innerErr != nil {
// 			return fail.Wrap(innerErr)
// 		}
//
// 		innerXErr := s.unsafeRegisterResource(casted)
// 		if innerXErr != nil {
// 			return innerXErr
// 		}
//
// 		count++
// 		return nil
// 	})
// }

func (s *scope) AllAbstracts() ([]terraformerapi.Resource, fail.Error) {
	if valid.IsNull(s) {
		return nil, fail.InvalidInstanceError()
	}

	s.lock.RLock()
	defer s.lock.RUnlock()

	list := make([]terraformerapi.Resource, 0, s.resourceByID.Size())
	s.resourceByID.Range(func(key string, value terraformerapi.Resource) bool {
		list = append(list, value)
		return true
	})

	return list, nil
}

func (s *scope) RegisterResource(rsc terraformerapi.Resource) fail.Error {
	if valid.IsNull(s) {
		return fail.InvalidInstanceError()
	}
	if valid.IsNull(rsc) {
		return fail.InvalidParameterCannotBeNilError("rsc")
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	return s.unsafeRegisterResource(rsc)
}

func (s *scope) unsafeRegisterResource(rsc terraformerapi.Resource) fail.Error {
	kind, name, queryID, queryName, xerr := buildResourceIndexes(rsc)
	if xerr != nil {
		return xerr
	}

	// Check duplicate by name
	storedID, found := s.resourceByName.Load(queryName)
	if found {
		_, found = s.resourceByID.Load(storedID)
		if found {
			return fail.DuplicateError("a %s named '%s' is already registered", kind, name)
		}
	}

	// check duplicate by id
	_, found = s.resourceByID.Load(queryID)
	if found {
		return fail.DuplicateError("a %s named '%s' is already registered", kind, name)
	}

	// Now registers resource
	s.resourceByID.Store(queryID, rsc)
	s.resourceByName.Store(queryName, queryID)
	return nil
}

func (s *scope) UnregisterResource(rsc terraformerapi.Resource) fail.Error {
	if valid.IsNull(s) {
		return fail.InvalidInstanceError()
	}
	if valid.IsNull(rsc) {
		return fail.InvalidParameterCannotBeNilError("rsc")
	}

	_, _, queryID, queryName, xerr := buildResourceIndexes(rsc)
	if xerr != nil {
		return xerr
	}

	// Check duplicate by name
	s.lock.Lock()
	defer s.lock.Unlock()

	s.resourceByName.Delete(queryName)
	s.resourceByID.Delete(queryID)
	return nil
}

// buildResourceIndexes returns kind, name, queryID and queryName corresponding to resource
func buildResourceIndexes(rsc terraformerapi.Resource) (string, string, string, string, fail.Error) {
	if valid.IsNull(rsc) {
		return "", "", "", "", fail.InvalidParameterCannotBeNilError("rsc")
	}

	kind := rsc.Kind()

	id, err := rsc.GetID()
	if err != nil {
		return "", "", "", "", fail.Wrap(err)
	}

	queryID := kind + ":" + id

	name := rsc.GetName()
	queryName := kind + ":" + name

	return kind, name, queryID, queryName, nil
}
