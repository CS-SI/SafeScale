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

package clusterproperty

// Enum represents the type of a node
type Enum string

const (
	// DescriptionV1 contains optional additional info describing cluster (purpose, ...)
	DescriptionV1 Enum = "1"
	// DefaultsV1 contains additional info about default settings (node sizing, default image, ...)
	DefaultsV1 = "2" // DEPRECATED: deprecated by DefaultsV2 (but kept for compatibility)
	// CompositeV1 contains optional additional info about the composite build of the cluster (multi-tenant)
	CompositeV1 = "3"
	// FeaturesV1 contains optional additional info describing installed features on cluster
	FeaturesV1 = "4"
	// NasV1 contains optional additional info describing Nas and shared folders on cluster
	NasV1 = "5"
	// NodesV1 contains optional additional info describing Nodes inside the cluster
	NodesV1 = "6"
	// StateV1 contains optional additional info describing cluster state
	StateV1 = "7"
	// NetworkV1 contains optional additional info about network of the cluster
	NetworkV1 = "8" // DEPRECATED: deprecated by NetworkV2 (but kept for compatibility)
	// DefaultsV2 contains optional additional info about default settings of the cluster
	DefaultsV2 = "9" // DEPRECATED: deprecated by DefaultV3 (but kept for compatibility)
	// NetworkV2 contains optional additional info about network of the cluster
	NetworkV2 = "10" // DEPRECATED: deprecated by NetworkV3 (but kept for compatibility)
	// NodesV2 contains optional additional info describing Nodes inside the cluster
	NodesV2 = "11" // DEPRECATED: deprecated by NodesV3 (but kept for compatibility)
	// ControlPlaneV1 contains optional additional info describing control plane settings inside the cluster
	ControlPlaneV1 = "12"
	// NetworkV3 contains optional additional info about network of the cluster
	NetworkV3 = "13"
	// NodesV3 contains optional additional info about network of the cluster
	NodesV3 = "14"
	// DefaultsV3 contains optional additional info about default settings of the cluster
	DefaultsV3 = "15"
)
