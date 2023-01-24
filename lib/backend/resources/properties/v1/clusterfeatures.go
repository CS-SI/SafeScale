/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// ClusterInstalledFeature ...
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//
//	Create a new version instead with needed supplemental/overriding fields
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
// satisfies interface clonable.Clonable
func (cif *ClusterInstalledFeature) IsNull() bool {
	return cif == nil || cif.Name == ""
}

// Clone ...
// satisfies interface clonable.Clonable
func (cif ClusterInstalledFeature) Clone() (clonable.Clonable, error) {
	ncif := NewClusterInstalledFeature()
	return ncif, ncif.Replace(&cif)
}

// Replace ...
// satisfies interface clonable.Clonable
func (cif *ClusterInstalledFeature) Replace(p clonable.Clonable) error {
	if cif == nil {
		return fail.InvalidInstanceError()
	}

	src, err := clonable.Cast[*ClusterInstalledFeature](p)
	if err != nil {
		return err
	}

	cif.RequiredBy = make(map[string]struct{}, len(src.RequiredBy))
	for k := range src.RequiredBy {
		cif.RequiredBy[k] = struct{}{}
	}
	cif.Requires = make(map[string]struct{}, len(src.Requires))
	for k := range src.Requires {
		cif.Requires[k] = struct{}{}
	}
	return nil
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
// satisfies interface clonable.Clonable
func (f *ClusterFeatures) IsNull() bool {
	return f == nil || (len(f.Installed) == 0 && len(f.Disabled) == 0)
}

// Clone ...
// satisfies interface clonable.Clonable
func (f *ClusterFeatures) Clone() (clonable.Clonable, error) {
	if f == nil {
		return nil, fail.InvalidInstanceError()
	}

	ncf := newClusterFeatures()
	return ncf, ncf.Replace(f)
}

// Replace ...
// satisfies interface clonable.Clonable
func (f *ClusterFeatures) Replace(p clonable.Clonable) error {
	if f == nil {
		return fail.InvalidInstanceError()
	}

	src, err := clonable.Cast[*ClusterFeatures](p)
	if err != nil {
		return err
	}

	f.Installed = make(map[string]*ClusterInstalledFeature, len(src.Installed))
	for k, v := range src.Installed {
		cloned, err := clonable.CastedClone[*ClusterInstalledFeature](v)
		if err != nil {
			return err
		}

		f.Installed[k] = cloned
	}
	f.Disabled = make(map[string]struct{}, len(src.Disabled))
	for k, v := range src.Disabled {
		f.Disabled[k] = v
	}
	return nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.cluster", clusterproperty.FeaturesV1, newClusterFeatures())
}
