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

	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// HostTags contains the list of tags on the host
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostTags struct {
	ByID   map[string]string `json:"by_id,omitempty"`   // map of tags by Id
	ByName map[string]string `json:"by_name,omitempty"` // map of tags IDs by Name
}

// NewHostTags ...
func NewHostTags() *HostTags {
	return &HostTags{
		ByID:   map[string]string{},
		ByName: map[string]string{},
	}
}

// IsNull ...
func (htag *HostTags) IsNull() bool {
	return htag == nil || len(htag.ByID) == 0
}

// Clone ...
func (htag HostTags) Clone() (data.Clonable, error) {
	return NewHostTags().Replace(&htag)
}

// Replace ...
func (htag *HostTags) Replace(p data.Clonable) (data.Clonable, error) {
	if htag == nil || p == nil {
		return nil, fail.InvalidInstanceError()
	}

	src, ok := p.(*HostTags)
	if !ok {
		return nil, fmt.Errorf("p is not a *HostTags")
	}

	*htag = *src
	htag.ByID = make(map[string]string, len(src.ByID))
	for k, v := range src.ByID {
		htag.ByID[k] = v
	}
	htag.ByName = make(map[string]string, len(src.ByName))
	for k, v := range src.ByName {
		htag.ByName[k] = v
	}
	return htag, nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.host", hostproperty.TagsV1, NewHostTags())
}
