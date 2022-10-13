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

package common

import (
	"path/filepath"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/global"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// Scope contains information about context of the Job
type Scope struct {
	organization string
	project      string
	tenant       string
	description  string
	kvPath       string
	fsPath       string
}

func NewScope(organization, project, tenant, description string) (Scope, fail.Error) {
	if organization == "" {
		organization = global.DefaultOrganization
	}
	if project == "" {
		project = global.DefaultProject
	}
	if tenant == "" {
		return Scope{}, fail.InvalidParameterCannotBeEmptyStringError("tenant")
	}

	out := Scope{
		organization: organization,
		project:      project,
		tenant:       tenant,
		description:  description,
		fsPath:       filepath.Join(organization, project, tenant),
		kvPath:       strings.Join([]string{organization, project, tenant}, "/"),
	}
	return out, nil
}

// IsNull ...
func (s *Scope) IsNull() bool {
	return s == nil || s.organization == "" || s.project == "" || s.tenant == ""
}

// Organization returns the organization of the Scope
func (s Scope) Organization() string {
	return s.organization
}

// Project returns the project of the Scope
func (s Scope) Project() string {
	return s.project
}

// Tenant returns the tenant of the Scope
func (s Scope) Tenant() string {
	return s.tenant
}

// Description returns the description of the Scope
func (s Scope) Description() string {
	return s.description
}

// KVPath returns the prefix path of the Scope in K/V store
func (s Scope) KVPath() string {
	return s.kvPath
}

// FSPath returns the prefix path of the Scope for FS use
func (s Scope) FSPath() string {
	return s.fsPath
}
