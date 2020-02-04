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

package property

//Enum represents the type of a node
type Enum string

const (
	// DescriptionV1 contains optional additional info describing cluster (purpose, ...)
	DescriptionV1 Enum = "1"
	// DefaultsV1 contains additional info about default settings (node sizing, default image, ...)
	// Deprecated by DefaultsV2 (but kept for compatibility)
	DefaultsV1 = "2"
	// CompositeV1 contains optional additional info about the composite build of the cluster (multi-tenant)
	CompositeV1 = "3"
	// FeaturesV1 contains optional additional info describing installed features on cluster
	FeaturesV1 = "4"
	// NasV1 contains optional additional info describing Nases and shared folders on cluster
	NasV1 = "5"
	// NodesV1 contains optional additional info describing Nodes inside the cluster
	NodesV1 = "6"
	// StateV1 contains optional additional info describing cluster state
	StateV1 = "7"
	// NetworkV1 contains optional additional info about network of the cluster
	NetworkV1 = "8"
	// DefaultsV2 contains optional additional info about network of the cluster
	DefaultsV2 = "9"
	// NetworkV2 contains optional additional info about network of the cluster (vip)
	NetworkV2 = "10"
	// ControlPlaneV1 contains optional additional info about Control Plane of the cluster
	ControlPlaneV1 = "11"
	// NodesV2 contains optional additional info describing Nodes inside the cluster
	NodesV2 = "12"
)
