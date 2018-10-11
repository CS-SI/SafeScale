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
	// Description contains optional additional info describing cluster (purpose, ...)
	Description Enum = iota
	// Flavor contains optional additional info used by the cluster manager software
	Flavor
	// Features contains optional additional info describing installed features on cluster
	Features
)
