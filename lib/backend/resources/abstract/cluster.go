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
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const ClusterKind = "cluster"

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

// CleanOnFailure tells if request asks for cleaning created ressource on failure
func (cr ClusterRequest) CleanOnFailure() bool {
	return !cr.KeepOnFailure
}

// Cluster contains the bare minimum information about a cluster
type Cluster struct {
	*core
	Flavor        clusterflavor.Enum     `json:"flavor"`         // Flavor tells what kind of cluster it is
	Complexity    clustercomplexity.Enum `json:"complexity"`     // Complexity is the mode of cluster
	Keypair       *KeyPair               `json:"keypair"`        // Keypair contains the key-pair used inside the Cluster
	AdminPassword string                 `json:"admin_password"` // contains the password of the cladm account
}

// NewCluster ...
func NewCluster(opts ...Option) (*Cluster, fail.Error) {
	opts = append(opts, withKind(ClusterKind))
	c, xerr := newCore(opts...)
	if xerr != nil {
		return nil, xerr
	}

	out := &Cluster{
		core: c,
	}
	out.Tags["CreationDate"] = time.Now().Format(time.RFC3339)
	out.Tags["ManagedBy"] = "safescale"
	return out, nil
}

// NewEmptyCluster returns a empty, unnamed Cluster instance
func NewEmptyCluster() *Cluster {
	out, _ := NewCluster()
	return out
}

// IsNull ...
func (instance *Cluster) IsNull() bool {
	return instance == nil || instance.core.IsNull() || (instance.Flavor != clusterflavor.K8S && instance.Flavor != clusterflavor.BOH)
}

// Clone makes a copy of the instance
// satisfies interface clonable.Clonable
func (instance *Cluster) Clone() (clonable.Clonable, error) {
	if instance == nil {
		return nil, fail.InvalidInstanceError()
	}

	nc, _ := NewCluster()
	return nc, nc.Replace(instance)
}

// Replace replaces the content of the instance with the content of the parameter
// satisfies interface clonable.Clonable
func (instance *Cluster) Replace(p clonable.Clonable) error {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if p == nil {
		return fail.InvalidParameterCannotBeNilError("p")
	}

	src, err := clonable.Cast[*Cluster](p)
	if err != nil {
		return err
	}

	*instance = *src
	instance.core, err = clonable.CastedClone[*core](src.core)
	if err != nil {
		return err
	}

	instance.Keypair = nil
	if src.Keypair != nil {
		instance.Keypair = &KeyPair{}
		*instance.Keypair = *src.Keypair
	}
	return nil
}

// // GetName returns the name of the cluster
// // Satisfies interface data.Identifiable
// func (instance *Cluster) GetName() string {
// 	if instance == nil || valid.IsNull(instance.Core) {
// 		return ""
// 	}
//
// 	return instance.Name
// }

// GetID returns the ID of the cluster (== GetName)
// Satisfies interface data.Identifiable
func (instance Cluster) GetID() (string, error) {
	return instance.GetName(), nil
}

// OK ...
func (instance Cluster) OK() bool {
	result := true
	result = result && instance.Name != ""
	result = result && instance.Flavor != 0
	return result
}

// Serialize serializes Cluster instance into bytes (output json code)
func (instance *Cluster) Serialize() ([]byte, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	r, jserr := json.Marshal(instance)
	if jserr != nil {
		return nil, fail.NewError(jserr.Error())
	}
	return r, nil
}

// Deserialize reads json code and reinstantiates a Cluster
func (instance *Cluster) Deserialize(buf []byte) (ferr fail.Error) {
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
