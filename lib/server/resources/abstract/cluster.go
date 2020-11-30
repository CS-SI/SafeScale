/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

package abstract

import (
	"encoding/json"

	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// ClusterRequest defines what kind of Cluster is wanted
type ClusterRequest struct {
	// GetName is the name of the cluster wanted
	Name string
	// CIDR defines the network to create
	CIDR string
	// Domain ...
	Domain string
	// Complexity is the implementation wanted, can be Small, Normal or Large
	Complexity clustercomplexity.Enum
	// Flavor tells what kind of cluster to create
	Flavor clusterflavor.Enum
	// NetworkID is the ID of the network to use
	NetworkID string
	// Tenant contains the name of the tenant
	Tenant string
	// KeepOnFailure is set to True to keep resources on cluster creation failure
	KeepOnFailure bool
	// GatewaysDef count
	GatewaysDef HostSizingRequirements
	// NodesDef count
	MastersDef HostSizingRequirements
	// NodesDef count
	NodesDef HostSizingRequirements
	// OS contains the name of the linux distribution wanted
	OS string
	// DisabledDefaultFeatures contains the list of features that should be installed by default but we don't want actually
	DisabledDefaultFeatures map[string]struct{}
}

// ClusterIdentity contains the bare minimum information about a cluster
type ClusterIdentity struct {
	Name       string                 `json:"name"`       // GetName is the name of the cluster
	Flavor     clusterflavor.Enum     `json:"flavor"`     // Flavor tells what kind of cluster it is
	Complexity clustercomplexity.Enum `json:"complexity"` // Complexity is the mode of cluster
	Keypair    *KeyPair               `json:"keypair"`    // Keypair contains the key-pair used inside the Cluster
	// AdminPassword contains the password of 'cladm' account. This password is used to connect via Guacamole, but cannot be used with SSH (by choice)
	AdminPassword string `json:"admin_password"`
}

// NewClusterIdentity ...
func NewClusterIdentity() *ClusterIdentity {
	return &ClusterIdentity{}
}

// IsNull ...
func (i *ClusterIdentity) IsNull() bool {
	return i == nil || i.Name == ""
}

// Clone makes a copy of the instance
// satisfies interface data.Clonable
func (i ClusterIdentity) Clone() data.Clonable {
	return NewClusterIdentity().Replace(&i)
}

// Replace replaces the content of the instance with the content of the parameter
// satisfies interface data.Clonable
func (i *ClusterIdentity) Replace(p data.Clonable) data.Clonable {
	// Do not test with IsNull(), it's allowed to clone a null value...
	if i == nil || p == nil {
		return i
	}

	src := p.(*ClusterIdentity)
	*i = *src
	i.Keypair = &KeyPair{}
	if src.Keypair != nil {
		i.Keypair = &KeyPair{}
		*i.Keypair = *src.Keypair
	}
	return i
}

// GetName returns the name of the cluster
// Satisfies interface data.Identifiable
func (i ClusterIdentity) GetName() string {
	return i.Name
}

// GetID returns the ID of the cluster (== GetName)
// Satisfies interface data.Identifiable
func (i ClusterIdentity) GetID() string {
	return i.GetName()
}

// OK ...
func (i ClusterIdentity) OK() bool {
	result := true
	result = result && i.Name != ""
	result = result && i.Flavor != 0
	return result
}

// Serialize serializes IPAddress instance into bytes (output json code)
func (i *ClusterIdentity) Serialize() ([]byte, fail.Error) {
	if i.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	r, jserr := json.Marshal(i)
	if jserr != nil {
		return nil, fail.NewError(jserr.Error())
	}
	return r, nil
}

// Deserialize reads json code and reinstantiates an IPAddress
func (i *ClusterIdentity) Deserialize(buf []byte) (xerr fail.Error) {
	// i cannot be nil, but can be null value (which will be filled by this method)
	if i == nil {
		return fail.InvalidInstanceError()
	}

	defer fail.OnPanic(&xerr)

	jserr := json.Unmarshal(buf, i)
	if jserr != nil {
		switch jserr.(type) {
		case *json.SyntaxError:
			return fail.SyntaxError(jserr.Error())
		default:
			return fail.NewError(jserr.Error())
		}
	}
	return nil
}
