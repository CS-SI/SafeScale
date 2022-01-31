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

package abstract

import (
	stdjson "encoding/json"
	"time"

	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// ClusterRequest defines what kind of Cluster is wanted
type ClusterRequest struct {
	Name                    string                 // contains the name of the cluster wanted
	CIDR                    string                 // defines the network to create
	Domain                  string                 // ...
	Complexity              clustercomplexity.Enum // is the implementation wanted, can be Small, Normal or Large
	Flavor                  clusterflavor.Enum     // tells what kind of cluster to create
	NetworkID               string                 // is the ID of the network to use; may be empty and in this case a new Network will be created
	Tenant                  string                 // contains the name of the tenant
	KeepOnFailure           bool                   // tells if resources have to be kept in case of failure (for further analysis)
	GatewaysDef             HostSizingRequirements // sizing of gateways
	MastersDef              HostSizingRequirements // sizing of Masters
	NodesDef                HostSizingRequirements // sizing of nodes
	InitialNodeCount        uint                   // contains the initial count of nodes to create (cannot be less than flavor requirement)
	OS                      string                 // contains the name of the linux distribution wanted
	DisabledDefaultFeatures map[string]struct{}    // contains the list of features that should be installed by default but we don't want actually
	Force                   bool                   // set to True in order to ignore sizing recommendations
	FeatureParameters       []string               // contains parameter values of automatically installed Features
}

// ClusterIdentity contains the bare minimum information about a cluster
type ClusterIdentity struct {
	Name          string                 `json:"name"`           // Name is the name of the cluster
	Flavor        clusterflavor.Enum     `json:"flavor"`         // Flavor tells what kind of cluster it is
	Complexity    clustercomplexity.Enum `json:"complexity"`     // Complexity is the mode of cluster
	Keypair       *KeyPair               `json:"keypair"`        // Keypair contains the key-pair used inside the Cluster
	AdminPassword string                 `json:"admin_password"` // contains the password of the cladm account
	Tags          map[string]string      `json:"tags,omitempty"`
}

// NewClusterIdentity ...
func NewClusterIdentity() *ClusterIdentity {
	ci := &ClusterIdentity{
		Tags: make(map[string]string),
	}
	ci.Tags["CreationDate"] = time.Now().Format(time.RFC3339)
	ci.Tags["ManagedBy"] = "safescale"
	return ci
}

// IsNull ...
func (self *ClusterIdentity) IsNull() bool {
	return self == nil || self.Name == ""
}

// Clone makes a copy of the instance
// satisfies interface data.Clonable
func (self ClusterIdentity) Clone() data.Clonable {
	return NewClusterIdentity().Replace(&self)
}

// Replace replaces the content of the instance with the content of the parameter
// satisfies interface data.Clonable
func (self *ClusterIdentity) Replace(p data.Clonable) data.Clonable {
	// Do not test with isNull(), it's allowed to clone a null value...
	if self == nil || p == nil {
		return self
	}

	// FIXME, Replace should also return an error
	src, _ := p.(*ClusterIdentity) // nolint
	*self = *src
	self.Keypair = nil
	if src.Keypair != nil {
		self.Keypair = &KeyPair{}
		*self.Keypair = *src.Keypair
	}
	return self
}

// GetName returns the name of the cluster
// Satisfies interface data.Identifiable
func (self ClusterIdentity) GetName() string {
	return self.Name
}

// GetID returns the ID of the cluster (== GetName)
// Satisfies interface data.Identifiable
func (self ClusterIdentity) GetID() string {
	return self.GetName()
}

// OK ...
func (self ClusterIdentity) OK() bool {
	result := true
	result = result && self.Name != ""
	result = result && self.Flavor != 0
	return result
}

// Serialize serializes ClusterIdentity instance into bytes (output json code)
func (self *ClusterIdentity) Serialize() ([]byte, fail.Error) {
	if self.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	r, jserr := json.Marshal(self)
	if jserr != nil {
		return nil, fail.NewError(jserr.Error())
	}
	return r, nil
}

// Deserialize reads json code and reinstantiates a ClusterIdentity
func (self *ClusterIdentity) Deserialize(buf []byte) (xerr fail.Error) {
	// self cannot be nil, but can be null value (which will be filled by this method)
	if self == nil {
		return fail.InvalidInstanceError()
	}

	defer fail.OnPanic(&xerr)

	jserr := json.Unmarshal(buf, self)
	if jserr != nil {
		switch jserr.(type) {
		case *stdjson.SyntaxError:
			return fail.SyntaxError(jserr.Error())
		default:
			return fail.NewError(jserr.Error())
		}
	}
	return nil
}
