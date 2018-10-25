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

package Extension

//go:generate stringer -type=Enum

// Enum represents the type of additional info for an host
type Enum uint8

const (
	_ Enum = iota
	// DescriptionV1 contains optional additional info describing cluster (purpose, ...)
	DescriptionV1
	// FlavorV1 contains optional additional info used by the cluster manager software
	FlavorV1
	// FeaturesV1 contains optional additional info describing installed features on cluster
	FeaturesV1
	// NasV1 contains optional additional info describing Nas and shared folders on cluster
	NasV1
)
