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

package providers

//Enum represents the provider of the tested driver
type Enum int

const (
	_ Enum = iota
	// OVH ...
	OVH
	// CLOUDFERRO ...
	CLOUDFERRO
	// FLEXIBLEENGINE ...
	FLEXIBLEENGINE
	// LOCAL ...
	LOCAL
)
