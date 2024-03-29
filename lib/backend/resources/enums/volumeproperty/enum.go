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

package volumeproperty

// Enum represents the type of a node
type Enum string

const (
	// DescriptionV1 specifies optional additional info describing volume (purpose, ...)
	DescriptionV1 = "1"
	// AttachedV1 contains additional information about hosts attaching the volume
	AttachedV1 = "2"
)
