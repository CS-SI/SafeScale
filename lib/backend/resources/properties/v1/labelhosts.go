/*
 * Copyright 2018-2023, CS Systemes d'Information, http://ctagroup.eu
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

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/labelproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// LabelHosts contains the values associated with Host bound to the Label
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//
//	Create a new version instead with needed supplemental fields
type LabelHosts struct {
	ByID   map[string]string `json:"by_id"`   // map of Label value indexed on Host ID
	ByName map[string]string `json:"by_name"` // map of Label values indexed on Host Name
}

// NewLabelHosts ...
func NewLabelHosts() *LabelHosts {
	return &LabelHosts{
		ByID:   map[string]string{},
		ByName: map[string]string{},
	}
}

// IsNull ...
func (hlabel *LabelHosts) IsNull() bool {
	return hlabel == nil || len(hlabel.ByID) == 0
}

// Clone ...
func (hlabel LabelHosts) Clone() (data.Clonable, error) {
	return NewLabelHosts().Replace(&hlabel)
}

// Replace ...
func (hlabel *LabelHosts) Replace(p data.Clonable) (data.Clonable, error) {
	if hlabel == nil || p == nil {
		return nil, fail.InvalidInstanceError()
	}

	src, ok := p.(*LabelHosts)
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
	serialize.PropertyTypeRegistry.Register("resources.label", labelproperty.HostsV1, NewLabelHosts())
}
