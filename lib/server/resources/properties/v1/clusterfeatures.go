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

	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data/serialize"
)

// ClusterInstalledFeature ...
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental/overriding fields
type ClusterInstalledFeature struct {
	Name       string              `json:"name"`                  // contains the name of the feature
	FileName   string              `json:"filename"`              // contains name of file used
	RequiredBy map[string]struct{} `json:"required_by,omitempty"` // tells what feature(s) needs this one
	Requires   map[string]struct{} `json:"requires,omitempty"`    // tells what feature(s) is(are) required by this one
}

// NewClusterInstalledFeature ...
func NewClusterInstalledFeature() *ClusterInstalledFeature {
	return &ClusterInstalledFeature{
		RequiredBy: map[string]struct{}{},
		Requires:   map[string]struct{}{},
	}
}

// IsNull ...
// satisfies interface data.Clonable
func (cif *ClusterInstalledFeature) IsNull() bool {
	return cif == nil || cif.Name == ""
}

// Clone ...
// satisfies interface data.Clonable
func (cif ClusterInstalledFeature) Clone() (data.Clonable, error) {
	return NewClusterInstalledFeature().Replace(&cif)
}

// Replace ...
// satisfies interface data.Clonable
func (cif *ClusterInstalledFeature) Replace(p data.Clonable) (data.Clonable, error) {
	// Do not test with isNull(), it's allowed to clone a null value...
	if cif == nil || p == nil {
		return cif, nil
	}

	src, ok := p.(*ClusterInstalledFeature)
	if !ok {
		return nil, fmt.Errorf("p is not a *ClusterInstalledFeature")
	}

	cif.RequiredBy = make(map[string]struct{}, len(src.RequiredBy))
	for k := range src.RequiredBy {
		cif.RequiredBy[k] = struct{}{}
	}
	cif.Requires = make(map[string]struct{}, len(src.Requires))
	for k := range src.Requires {
		cif.Requires[k] = struct{}{}
	}
	return cif, nil
}

// ClusterFeatures ...
// not FROZEN yet
type ClusterFeatures struct {
	// Installed ...
	Installed map[string]*ClusterInstalledFeature `json:"installed"`
	// Disabled keeps track of features normally automatically added with cluster creation,
	// but explicitly disabled; if a disabled feature is added, must be removed from this property
	Disabled map[string]struct{} `json:"disabled"`
}

func newClusterFeatures() *ClusterFeatures {
	return &ClusterFeatures{
		Installed: map[string]*ClusterInstalledFeature{},
		Disabled:  map[string]struct{}{},
	}
}

// IsNull ...
// satisfies interface data.Clonable
func (f *ClusterFeatures) IsNull() bool {
	return f == nil || (len(f.Installed) == 0 && len(f.Disabled) == 0)
}

// Clone ...
// satisfies interface data.Clonable
func (f ClusterFeatures) Clone() (data.Clonable, error) {
	return newClusterFeatures().Replace(&f)
}

// Replace ...
// satisfies interface data.Clonable
func (f *ClusterFeatures) Replace(p data.Clonable) (data.Clonable, error) {
	// Do not test with isNull(), it's allowed to clone a null value...
	if f == nil || p == nil {
		return f, nil
	}

	src, ok := p.(*ClusterFeatures)
	if !ok {
		return nil, fmt.Errorf("p is not a *ClusterFeatures")
	}

	f.Installed = make(map[string]*ClusterInstalledFeature, len(src.Installed))
	for k, v := range src.Installed {
		cloned, err := v.Clone()
		if err != nil {
			return nil, err
		}
		f.Installed[k], ok = cloned.(*ClusterInstalledFeature)
		if !ok {
			return nil, fmt.Errorf("cloned is not a *ClusterInstalledFeature")
		}
	}
	f.Disabled = make(map[string]struct{}, len(src.Disabled))
	for k, v := range src.Disabled {
		f.Disabled[k] = v
	}
	return f, nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.cluster", clusterproperty.FeaturesV1, newClusterFeatures())
}
