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

package propertiesv2

import (
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/property"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// Defaults stores default information about cluster
// FIXME: make sure there is code to migrate propertiesv1.Network to propertiesv2.Network when needed
// !!! FROZEN !!!
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with updated/additional fields
type Defaults struct {
	// GatewaySizing keeps the default node sizing
	GatewaySizing resources.SizingRequirements `json:"gateway_sizing"`
	// MasterSizing keeps the default node sizing
	MasterSizing resources.SizingRequirements `json:"master_sizing"`
	// NodeSizing keeps the default node sizing
	NodeSizing resources.SizingRequirements `json:"node_sizing"`
	// Image keeps the default Linux image to use
	Image string `json:"image"`
}

func newDefaults() *Defaults {
	return &Defaults{}
}

// Content ...
// satisfies interface data.Clonable
func (d *Defaults) Content() data.Clonable {
	return d
}

// Clone ...
// satisfies interface data.Clonable
func (d *Defaults) Clone() data.Clonable {
	return newDefaults().Replace(d)
}

// Replace ...
// satisfies interface data.Clonable
func (d *Defaults) Replace(p data.Clonable) data.Clonable {
	*d = *p.(*Defaults)
	return d
}

func init() {
	serialize.PropertyTypeRegistry.Register("clusters", property.DefaultsV2, &Defaults{})
}
