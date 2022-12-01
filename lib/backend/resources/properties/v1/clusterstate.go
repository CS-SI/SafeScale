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

package propertiesv1

import (
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// ClusterState contains the bare minimum information about the state of a cluster
type ClusterState struct {
	State                clusterstate.Enum `json:"state,omitempty"`                  // State of the cluster
	StateCollectInterval time.Duration     `json:"state_collect_interval,omitempty"` // in seconds

}

func newClusterState() *ClusterState {
	return &ClusterState{}
}

// IsNull ...
// satisfies interface clonable.Clonable
func (s *ClusterState) IsNull() bool {
	return s == nil || (s.StateCollectInterval <= 0)
}

// Clone ...
// satisfies interface clonable.Clonable
func (s *ClusterState) Clone() (clonable.Clonable, error) {
	if s == nil {
		return nil, fail.InvalidInstanceError()
	}

	ncs := newClusterState()
	return ncs, ncs.Replace(s)
}

// Replace ...
// satisfies interface clonable.Clonable
func (s *ClusterState) Replace(p clonable.Clonable) error {
	if s == nil {
		return fail.InvalidInstanceError()
	}

	casted, err := clonable.Cast[*ClusterState](p)
	if err != nil {
		return err
	}

	*s = *casted
	return nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.cluster", clusterproperty.StateV1, newClusterState())
}
