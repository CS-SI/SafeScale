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
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Extension"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/utils/serialize"
)

// Defaults ...
type Defaults struct {
	// NodeSizing keeps the default node definition
	NodeSizing model.HostSize `json:"node_sizing"`
	// Image keeps the default Linux image to use
	Image string `json:"image"`
}

// Content ... (serialize.Property interface)
func (n *Defaults) Content() interface{} {
	return n
}

// Clone ... (serialize.Property interface)
func (n *Defaults) Clone() serialize.Property {
	nn := &Defaults{}
	*nn = *n
	return nn
}

// Replace ... (serialize.Property interface)
func (n *Defaults) Replace(v interface{}) {
	*n = *(v.(*Defaults))
}

func init() {
	serialize.PropertyTypeRegistry.Register("clusters", Extension.DefaultsV1, &Defaults{})
}
