/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

// State contains the bare minimum information about a cluster
type State struct {
	// State of the cluster
	State clusterstate.Enum
	// StateCollectInterval in seconds
	StateCollectInterval time.Duration `json:"state_collect_interval,omitempty"`
}

func newState() *State {
	return &State{}
}

// Content ... (data.Clonable interface)
func (s *State) Content() interface{} {
	return s
}

// Clone ... (data.Clonable interface)
func (s *State) Clone() data.Clonable {
	return newState().Replace(s)
}

// Replace ... (data.Clonable interface)
func (s *State) Replace(p data.Clonable) data.Clonable {
	*s = *p.(*State)
	return s
}

func init() {
	serialize.PropertyTypeRegistry.Register("clusters", clusterproperty.StateV1, &State{})
}
