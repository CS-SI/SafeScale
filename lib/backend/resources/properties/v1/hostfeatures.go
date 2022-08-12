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
	"fmt"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// HostInstalledFeature ...
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental/overriding fields
type HostInstalledFeature struct {
	HostContext bool                `json:"host_context,omitempty"` // tells if the feature has been explicitly installed for host (opposed to for cluster)
	RequiredBy  map[string]struct{} `json:"required_by,omitempty"`  // tells what feature(s) needs this one
	Requires    map[string]struct{} `json:"requires,omitempty"`
}

// NewHostInstalledFeature ...
func NewHostInstalledFeature() *HostInstalledFeature {
	return &HostInstalledFeature{
		RequiredBy: make(map[string]struct{}),
		Requires:   make(map[string]struct{}),
	}
}

// IsNull ...
// satisfies interface data.Clonable
func (hif *HostInstalledFeature) IsNull() bool {
	return hif == nil || (len(hif.RequiredBy) == 0 && len(hif.Requires) == 0) || hif.RequiredBy == nil || hif.Requires == nil
}

// Clone ...
// satisfies interface data.Clonable
func (hif *HostInstalledFeature) Clone() (data.Clonable, error) {
	return NewHostInstalledFeature().Replace(hif)
}

// Replace ...
// satisfies interface data.Clonable
func (hif *HostInstalledFeature) Replace(p data.Clonable) (data.Clonable, error) {
	if hif == nil || p == nil {
		return nil, fail.InvalidInstanceError()
	}

	src, ok := p.(*HostInstalledFeature)
	if !ok {
		return nil, fmt.Errorf("p is not a *HostInstalledFeature")
	}

	hif.HostContext = src.HostContext
	hif.RequiredBy = make(map[string]struct{}, len(src.RequiredBy))
	for k := range src.RequiredBy {
		hif.RequiredBy[k] = struct{}{}
	}
	hif.Requires = make(map[string]struct{}, len(src.Requires))
	for k := range src.Requires {
		hif.Requires[k] = struct{}{}
	}
	return hif, nil
}

// HostFeatures ...
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostFeatures struct {
	Installed map[string]*HostInstalledFeature `json:"installed,omitempty"` // list of installed features, indexed on feature name
}

// NewHostFeatures ...
func NewHostFeatures() *HostFeatures {
	return &HostFeatures{
		Installed: map[string]*HostInstalledFeature{},
	}
}

// Reset resets the content of the property
func (hf *HostFeatures) Reset() {
	*hf = HostFeatures{
		Installed: map[string]*HostInstalledFeature{},
	}
}

// IsNull ...
// satisfies interface data.Clonable
func (hf *HostFeatures) IsNull() bool {
	return hf == nil || len(hf.Installed) == 0
}

// Clone ...  (data.Clonable interface)
func (hf HostFeatures) Clone() (data.Clonable, error) {
	return NewHostFeatures().Replace(&hf)
}

// Replace ...  (data.Clonable interface)
func (hf *HostFeatures) Replace(p data.Clonable) (data.Clonable, error) {
	if hf == nil || p == nil {
		return nil, fail.InvalidInstanceError()
	}

	src, ok := p.(*HostFeatures)
	if !ok {
		return nil, fmt.Errorf("p is not a *HostFeatures")
	}

	hf.Installed = make(map[string]*HostInstalledFeature, len(src.Installed))
	for k, v := range src.Installed {
		hf.Installed[k] = v
	}
	return hf, nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.host", hostproperty.FeaturesV1, NewHostFeatures())
}
