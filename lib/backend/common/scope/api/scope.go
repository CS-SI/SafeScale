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

package scopeapi

import (
	"github.com/CS-SI/SafeScale/v22/lib/backend/externals/consul/consumer"
	terraformerapi "github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// Scope ...
type Scope interface {
	ConsulKV() *consumer.KV
	Description() string
	ID() string
	IsLoaded() bool
	IsNull() bool
	FSPath() string
	KVPath() string
	Organization() string
	Project() string
	RegisterResource(terraformerapi.Resource) fail.Error
	ReplaceResource(terraformerapi.Resource) fail.Error
	Resource(kind, name string) (terraformerapi.Resource, fail.Error)
	Service() iaasapi.Service
	Tenant() string
	UnregisterResource(terraformerapi.Resource) fail.Error
}
