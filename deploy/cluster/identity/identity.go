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

package identity

import (
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Complexity"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Flavor"
	"github.com/CS-SI/SafeScale/providers/model"
)

// Identity contains the bare minimum information about a cluster
type Identity struct {
	Name       string          `json:"name"`       // Name is the name of the cluster
	Flavor     Flavor.Enum     `json:"flavor"`     // Flavor tells what kind of cluster it is
	Complexity Complexity.Enum `json:"complexity"` // Mode is the mode of cluster; can be Simple, HighAvailability, HighVolume
	Keypair    *model.KeyPair  `json:"keypair"`    // Keypair contains the key-pair used inside the Cluster

	// AdminPassword contains the password of cladm account. This password
	// is used to connect via Guacamole, but can't be used with SSH
	AdminPassword string `json:"admin_password"`
}
