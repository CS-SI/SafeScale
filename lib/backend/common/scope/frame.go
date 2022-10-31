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

package scope

import (
	"path/filepath"
	"strings"
	"sync"

	"github.com/CS-SI/SafeScale/v22/lib/backend/externals/consul/consumer"
	iaasapi "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/puzpuzpuz/xsync"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/global"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

var (
	frameList sync.Map
)

// Frame contains information about context of the Job
type Frame struct {
	organization   string
	project        string
	tenant         string
	description    string
	kvPath         string
	fsPath         string
	resourceByName xsync.MapOf[string, string]
	resourceByID   xsync.MapOf[string, resources.Core]
	consulClient   *consumer.Client
	consulKV       *consumer.KV
	service        iaasapi.Service
}

// Load returns an existing scope from scope list
func Load(organization, project, tenant string) (*Frame, fail.Error) {
	kvPath := buildKVPath(organization, project, tenant)
	entry, loaded := frameList.Load(kvPath)
	if !loaded {
		return nil, fail.NotFoundError("failed to find a Frame identified by '%s'", kvPath)
	}

	out, ok := entry.(*Frame)
	if !ok {
		return nil, fail.InconsistentError("loaded scope is not of type '*Frame'")
	}

	return out, nil
}

// buildKVPath assembles the path that will be used as KV prefix
func buildKVPath(organization, project, tenant string) string {
	return strings.Join([]string{organization, project, tenant}, "/")
}

// New creates a new scope
func New(organization, project, tenant, description string) (*Frame, fail.Error) {
	if organization == "" {
		organization = global.DefaultOrganization
	}
	if project == "" {
		project = global.DefaultProject
	}
	if tenant == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("tenant")
	}

	out := &Frame{
		organization: organization,
		project:      project,
		tenant:       tenant,
		description:  description,
		fsPath:       filepath.Join(organization, project, tenant),
		kvPath:       strings.Join([]string{organization, project, tenant}, "/"),
	}

	_, loaded := frameList.LoadOrStore(out.kvPath, out)
	if loaded {
		return nil, fail.DuplicateError("there is already a Frame '%s'", out.ID())
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

// IsNull tells if the Frame is considered as null value
func (s *Frame) IsNull() bool {
	return s == nil || s.organization == "" || s.project == "" || s.tenant == ""
}

// ID returns the scope identifier (which is equal to KVPath())
func (s *Frame) ID() string {
	if s.IsNull() {
		return ""
	}

	return s.kvPath
}

// Organization returns the organization of the Frame
func (s *Frame) Organization() string {
	if s.IsNull() {
		return ""
	}

	return s.organization
}

// Project returns the project of the Frame
func (s *Frame) Project() string {
	if s.IsNull() {
		return ""
	}

	return s.project
}

// Tenant returns the tenant of the Frame
func (s *Frame) Tenant() string {
	if s.IsNull() {
		return ""
	}

	return s.tenant
}

// Description returns the description of the Frame
func (s *Frame) Description() string {
	if s.IsNull() {
		return ""
	}

	return s.description
}

// KVPath returns the prefix path of the Frame in K/V store
func (s *Frame) KVPath() string {
	if s.IsNull() {
		return ""
	}

	return s.kvPath
}

// FSPath returns the prefix path of the Frame for FS use
func (s *Frame) FSPath() string {
	if s.IsNull() {
		return ""
	}

	return s.fsPath
}

func (s *Frame) Service() iaasapi.Service {
	if s.IsNull() {
		return nil
	}

	return s.service
}

func (s *Frame) ConsulKV() *consumer.KV {
	if valid.IsNull(s) {
		return nil
	}

	return s.consulKV
}
