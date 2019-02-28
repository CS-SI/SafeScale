/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package controller

import (
	"github.com/CS-SI/SafeScale/safescale/server/cluster/enums/Complexity"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/enums/Flavor"
	"github.com/CS-SI/SafeScale/iaas/resources"
)

// Request defines what kind of Cluster is wanted
type Request struct {
	// Name is the name of the cluster wanted
	Name string
	// CIDR defines the network to create
	CIDR string
	// Complexity is the implementation wanted, can be Small, Normal or Large
	Complexity Complexity.Enum
	// Flavor tells what kind of cluster to create
	Flavor Flavor.Enum
	// NetworkID is the ID of the network to use
	NetworkID string
	// Tenant contains the name of the tenant
	Tenant string
	// KeepOnFailure is set to True to keep resources on cluster creation failure
	KeepOnFailure bool
	// NodesDef count
	NodesDef *resources.HostDefinition
	// DisabledDefaultFeatures contains the list of features that should be installed by default but we don't want actually
	DisabledDefaultFeatures map[string]struct{}
}
