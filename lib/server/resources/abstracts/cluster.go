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

package abstracts

import (
	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/lib/utils/data"
)

//go:generate mockgen -destination=mocks/mock_cluster.go -package=mocks github.com/CS-SI/SafeScale/lib/server/resources/abstracts ClusterRequest

// ClusterRequest defines what kind of Cluster is wanted
type ClusterRequest struct {
	// Name is the name of the cluster wanted
	Name string
	// CIDR defines the network to create
	CIDR string
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
	GatewaysDef *protocol.HostDefinition
	// NodesDef count
	MastersDef *protocol.HostDefinition
	// NodesDef count
	NodesDef *protocol.HostDefinition
	// DisabledDefaultFeatures contains the list of features that should be installed by default but we don't want actually
	DisabledDefaultFeatures map[string]struct{}
}

// ClusterIdentity contains the bare minimum information about a cluster
type ClusterIdentity struct {
	Name       string                 `json:"name"`       // Name is the name of the cluster
	Flavor     clusterflavor.Enum     `json:"flavor"`     // Flavor tells what kind of cluster it is
	Complexity clustercomplexity.Enum `json:"complexity"` // Complexity is the mode of cluster
	Keypair    *KeyPair               `json:"keypair"`    // Keypair contains the key-pair used inside the Cluster
	// AdminPassword contains the password of cladm account. This password
	// is used to connect via Guacamole, but cannot be used with SSH
	AdminPassword string `json:"admin_password"`
}

// NewClusterIdentity ...
func NewClusterIdentity() *ClusterIdentity {
	return &ClusterIdentity{}
}

// Content ... (data.Clonable interface)
func (i *ClusterIdentity) Content() interface{} {
	return i
}

// Clone ... (data.Clonable interface)
func (i *ClusterIdentity) Clone() data.Clonable {
	return NewClusterIdentity().Replace(i)
}

// Replace ... (data.Clonable interface)
func (i *ClusterIdentity) Replace(p data.Clonable) data.Clonable {
	src := p.(*ClusterIdentity)
	*i = *src
	i.Keypair = &KeyPair{}
	*i.Keypair = *src.Keypair
	return i
}

// OK ...
func (i *ClusterIdentity) OK() bool {
	if i == nil {
		return false
	}

	result := true
	result = result && i.Name != ""
	result = result && i.Flavor != 0
	return result
}
