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
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/serialize"
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
		RequiredBy: map[string]struct{}{},
		Requires:   map[string]struct{}{},
	}
}

// Reset resets the content of the property
func (hif *HostInstalledFeature) Reset() {
	*hif = HostInstalledFeature{
		RequiredBy: map[string]struct{}{},
		Requires:   map[string]struct{}{},
	}
}

// Clone ...
// satisfies interface data.Clonable
func (hif HostInstalledFeature) Clone() data.Clonable {
	return NewClusterInstalledFeature().Replace(&hif)
}

// Replace ...
// satisfies interface data.Clonable
func (hif *HostInstalledFeature) Replace(p data.Clonable) data.Clonable {
	// Do not test with isNull(), it's allowed to clone a null value...
	if hif == nil || p == nil {
		return hif
	}

	src := p.(*HostInstalledFeature)
	hif.HostContext = src.HostContext
	hif.RequiredBy = make(map[string]struct{}, len(src.RequiredBy))
	for k := range src.RequiredBy {
		hif.RequiredBy[k] = struct{}{}
	}
	hif.Requires = make(map[string]struct{}, len(src.Requires))
	for k := range src.Requires {
		hif.Requires[k] = struct{}{}
	}
	return hif
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

// Clone ...  (data.Clonable interface)
func (hf HostFeatures) Clone() data.Clonable {
	return NewHostFeatures().Replace(&hf)
}

// Replace ...  (data.Clonable interface)
func (hf *HostFeatures) Replace(p data.Clonable) data.Clonable {
	// Do not test with isNull(), it's allowed to clone a null value...
	if hf == nil || p == nil {
		return hf
	}

	src := p.(*HostFeatures)
	hf.Installed = make(map[string]*HostInstalledFeature, len(src.Installed))
	for k, v := range src.Installed {
		hf.Installed[k] = v
	}
	return hf
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.host", hostproperty.FeaturesV1, NewHostFeatures())
}
