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

package abstract

import (
	stdjson "encoding/json"
	"fmt"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
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
	DisabledDefaultFeatures map[string]struct{}    // contains the list of features that should be installed by default, but we don't want actually
	Force                   bool                   // set to True in order to ignore sizing recommendations
	FeatureParameters       []string               // contains parameter values of automatically installed Features
	DefaultSshPort          uint                   // default ssh port for gateways // nolint
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
func (instance *ClusterIdentity) IsNull() bool {
	return instance == nil || instance.Name == ""
}

// Clone makes a copy of the instance
// satisfies interface data.Clonable
func (instance ClusterIdentity) Clone() (data.Clonable, error) {
	return NewClusterIdentity().Replace(&instance)
}

// Replace replaces the content of the instance with the content of the parameter
// satisfies interface data.Clonable
func (instance *ClusterIdentity) Replace(p data.Clonable) (data.Clonable, error) {
	if instance == nil || p == nil {
		return nil, fail.InvalidInstanceError()
	}

	src, ok := p.(*ClusterIdentity)
	if !ok {
		return nil, fmt.Errorf("p is not a *ClusterIdentity")
	}
	*instance = *src
	instance.Keypair = nil
	if src.Keypair != nil {
		instance.Keypair = &KeyPair{}
		*instance.Keypair = *src.Keypair
	}
	return instance, nil
}

// GetName returns the name of the cluster
// Satisfies interface data.Identifiable
func (instance ClusterIdentity) GetName() string {
	return instance.Name
}

// GetID returns the ID of the cluster (== GetName)
// Satisfies interface data.Identifiable
func (instance ClusterIdentity) GetID() (string, error) {
	return instance.GetName(), nil
}

// OK ...
func (instance ClusterIdentity) OK() bool {
	result := true
	result = result && instance.Name != ""
	result = result && instance.Flavor != 0
	return result
}

// Serialize serializes ClusterIdentity instance into bytes (output json code)
func (instance *ClusterIdentity) Serialize() ([]byte, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	r, jserr := json.Marshal(instance)
	if jserr != nil {
		return nil, fail.NewError(jserr.Error())
	}
	return r, nil
}

// Deserialize reads json code and reinstantiates a ClusterIdentity
func (instance *ClusterIdentity) Deserialize(buf []byte) (ferr fail.Error) {
	// instance cannot be nil, but can be null value (which will be filled by this method)
	if instance == nil {
		return fail.InvalidInstanceError()
	}

	defer fail.OnPanic(&ferr)

	jserr := json.Unmarshal(buf, instance)
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
