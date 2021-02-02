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
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// ClusterInstalledFeature ...
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental/overriding fields
type ClusterInstalledFeature struct {
	RequiredBy map[string]struct{} `json:"required_by,omitempty"` // tells what feature(s) needs this one
	Requires   map[string]struct{} `json:"requires,omitempty"`
}

// newClusterInstalledFeature ...
func newClusterInstalledFeature() *ClusterInstalledFeature {
	return &ClusterInstalledFeature{
		RequiredBy: map[string]struct{}{},
		Requires:   map[string]struct{}{},
	}
}

// Clone ...
// satisfies interface data.Clonable
func (cif ClusterInstalledFeature) Clone() data.Clonable {
	return newClusterInstalledFeature().Replace(&cif)
}

// Replace ...
// satisfies interface data.Clonable
func (cif *ClusterInstalledFeature) Replace(p data.Clonable) data.Clonable {
	// Do not test with IsNull(), it's allowed to clone a null value...
	if cif == nil || p == nil {
		return cif
	}

	src := p.(*ClusterInstalledFeature)
	cif.RequiredBy = make(map[string]struct{}, len(src.RequiredBy))
	for k := range src.RequiredBy {
		cif.RequiredBy[k] = struct{}{}
	}
	cif.Requires = make(map[string]struct{}, len(src.Requires))
	for k := range src.Requires {
		cif.Requires[k] = struct{}{}
	}
	return cif
}

// // Reset resets the content of the property
// func (p *HostInstalledFeature) Reset() {
// 	*p = HostInstalledFeature{
// 		RequiredBy: []string{},
// 		Requires:   []string{},
// 	}
// }

// ClusterFeatures ...
// not FROZEN yet
type ClusterFeatures struct {
	// Installed ...
	Installed map[string]*ClusterInstalledFeature `json:"installed"`
	// Disabled keeps track of features normally automatically added with cluster creation,
	// but explicitely disabled; if a disabled feature is added, must be removed from this property
	Disabled map[string]struct{} `json:"disabled"`
}

func newClusterFeatures() *ClusterFeatures {
	return &ClusterFeatures{
		Installed: map[string]*ClusterInstalledFeature{},
		Disabled:  map[string]struct{}{},
	}
}

// Clone ...
// satisfies interface data.Clonable
func (f ClusterFeatures) Clone() data.Clonable {
	return newClusterFeatures().Replace(&f)
}

// Replace ...
// satisfies interface data.Clonable
func (f *ClusterFeatures) Replace(p data.Clonable) data.Clonable {
	// Do not test with IsNull(), it's allowed to clone a null value...
	if f == nil || p == nil {
		return f
	}

	src := p.(*ClusterFeatures)
	f.Installed = make(map[string]*ClusterInstalledFeature, len(src.Installed))
	for k, v := range src.Installed {
		f.Installed[k] = v.Clone().(*ClusterInstalledFeature)
	}
	f.Disabled = make(map[string]struct{}, len(src.Disabled))
	for k, v := range src.Disabled {
		f.Disabled[k] = v
	}
	return f
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.cluster", clusterproperty.FeaturesV1, newClusterFeatures())
}
