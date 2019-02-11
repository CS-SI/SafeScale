/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Property"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/utils/serialize"
)

// Defaults ...
type Defaults struct {
	// GatewaySizing keeps the default node definition
	GatewaySizing model.HostDefinition `json:"gateway_sizing"`
	// MasterSizing keeps the default node definition
	MasterSizing model.HostDefinition `json:"master_sizing"`
	// NodeSizing keeps the default node definition
	NodeSizing model.HostDefinition `json:"node_sizing"`
	// Image keeps the default Linux image to use
	Image string `json:"image"`
}

func newDefaults() *Defaults {
	return &Defaults{}
}

// Content ... (serialize.Property interface)
func (d *Defaults) Content() interface{} {
	return d
}

// Clone ... (serialize.Property interface)
func (d *Defaults) Clone() serialize.Property {
	dn := newDefaults()
	err := serialize.CloneValue(d, dn)
	if err != nil {
		panic(fmt.Sprintf("failed to clone 'Defaults': %v", err))
	}
	return dn
}

// Replace ... (serialize.Property interface)
func (d *Defaults) Replace(v interface{}) {
	err := serialize.CloneValue(v, d)
	if err != nil {
		panic(fmt.Sprintf("failed to replace 'Defaults': %v", err))
	}
}

func init() {
	serialize.PropertyTypeRegistry.Register("clusters", Property.DefaultsV1, &Defaults{})
}
