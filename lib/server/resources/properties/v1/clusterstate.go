/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

package propertiesv1

import (
	"time"

	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// ClusterState contains the bare minimum information about a cluster
type ClusterState struct {
	// getState of the cluster
	State clusterstate.Enum
	// StateCollectInterval in seconds
	StateCollectInterval time.Duration `json:"state_collect_interval,omitempty"`
}

func newClusterState() *ClusterState {
	return &ClusterState{}
}

// Clone ...
// satisfies interface data.Clonable
func (s ClusterState) Clone() data.Clonable {
	return newClusterState().Replace(&s)
}

// Replace ...
// satisfies interface data.Clonable
func (s *ClusterState) Replace(p data.Clonable) data.Clonable {
	// Do not test with isNull(), it's allowed to clone a null value...
	if s == nil || p == nil {
		return s
	}

	*s = *p.(*ClusterState)
	return s
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.cluster", clusterproperty.StateV1, newClusterState())
}
