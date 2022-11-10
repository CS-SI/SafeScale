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
	"path/filepath"
	"strings"
	"sync"

	terraformerapi "github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer/api"
	"github.com/puzpuzpuz/xsync"

	"github.com/CS-SI/SafeScale/v22/lib/backend/externals/consul/consumer"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/global"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

var (
	scopeList sync.Map
)

// scope contains information about context of the Job
type scope struct {
	organization   string
	project        string
	tenant         string
	description    string
	kvPath         string
	fsPath         string
	resourceByName *xsync.MapOf[string, string]
	resourceByID   *xsync.MapOf[string, clonable.Clonable]
	consulClient   *consumer.Client
	consulKV       *consumer.KV
	service        iaasapi.Service
}

// Load returns an existing scope from scope list
func Load(organization, project, tenant string) (*scope, fail.Error) {
	kvPath := buildKVPath(organization, project, tenant)
	entry, loaded := scopeList.Load(kvPath)
	if !loaded {
		return nil, fail.NotFoundError("failed to find a Scope identified by '%s'", kvPath)
	}

	out, ok := entry.(*scope)
	if !ok {
		return nil, fail.InconsistentError("loaded scope is not of type '*Scope'")
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
		resourceByID:   xsync.NewMapOf[clonable.Clonable](),
		resourceByName: xsync.NewMapOf[string](),
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

// ID returns the scope identifier (which is equal to KVPath())
func (s *scope) ID() string {
	if s.IsNull() {
		return ""
	}

	return s.kvPath
}

// Organization returns the organization of the scope
func (s *scope) Organization() string {
	if s.IsNull() {
		return ""
	}

	return s.organization
}

// Project returns the project of the scope
func (s *scope) Project() string {
	if s.IsNull() {
		return ""
	}

	return s.project
}

// Tenant returns the tenant of the scope
func (s *scope) Tenant() string {
	if s.IsNull() {
		return ""
	}

	return s.tenant
}

// Description returns the description of the scope
func (s *scope) Description() string {
	if s.IsNull() {
		return ""
	}

	return s.description
}

// KVPath returns the prefix path of the scope in K/V store
func (s *scope) KVPath() string {
	if s.IsNull() {
		return ""
	}

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

	return s.service
}

func (s *scope) ConsulKV() *consumer.KV {
	if valid.IsNull(s) {
		return nil
	}

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

func (s *scope) AllResources() ([]terraformerapi.Resource, fail.Error) {
	if valid.IsNull(s) {
		return nil, fail.InvalidInstanceError()
	}

	ok := true
	list := make([]terraformerapi.Resource, 0, s.resourceByID.Size())
	s.resourceByID.Range(func(key string, value clonable.Clonable) bool {
		if !ok {
			return false
		}

		var item terraformerapi.Resource
		item, ok = value.(terraformerapi.Resource)
		if !ok {
			return false
		}

		list = append(list, item)
		return true
	})
	if !ok {
		return nil, fail.NewError("failed to cast to 'terraformerapi.Resource'")
	}

	return list, nil
}
