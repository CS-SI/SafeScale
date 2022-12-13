/*
 * Copyright 2018-2022, CS Systemes d'Information, http://ctagroup.eu
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
	"fmt"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// HostLabels contains the list of labels on the host
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//
//	Create a new version instead with needed supplemental fields
type HostLabels struct {
	ByID   map[string]string `json:"by_id,omitempty"`   // map of Label value for the Host indexed on Label ID
	ByName map[string]string `json:"by_name,omitempty"` // map of Label value for the Host indexed on Label Name
}

// NewHostLabels ...
func NewHostLabels() *HostLabels {
	return &HostLabels{
		ByID:   map[string]string{},
		ByName: map[string]string{},
	}
}

// IsNull ...
func (hlabel *HostLabels) IsNull() bool {
	return hlabel == nil || len(hlabel.ByID) == 0
}

// Clone ...
func (hlabel HostLabels) Clone() (data.Clonable, error) {
	return NewHostLabels().Replace(&hlabel)
}

// Replace ...
func (hlabel *HostLabels) Replace(p data.Clonable) (data.Clonable, error) {
	if hlabel == nil || p == nil {
		return nil, fail.InvalidInstanceError()
	}

	src, ok := p.(*HostLabels)
	if !ok {
		return nil, fmt.Errorf("p is not a *HostTags")
	}

	*hlabel = *src
	hlabel.ByID = make(map[string]string, len(src.ByID))
	for k, v := range src.ByID {
		hlabel.ByID[k] = v
	}
	hlabel.ByName = make(map[string]string, len(src.ByName))
	for k, v := range src.ByName {
		hlabel.ByName[k] = v
	}
	return hlabel, nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.host", hostproperty.LabelsV1, NewHostLabels())
}
