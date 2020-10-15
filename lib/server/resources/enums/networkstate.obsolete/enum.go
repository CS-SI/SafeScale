/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

package networkstate_obsolete

//go:generate stringer -type=Enum

// Enum represents the state of a network
type Enum int

const (
	// UNKNOWNSTATE
	UNKNOWNSTATE Enum = iota

	// GATEWAY_CREATION when gateway(s) is(are) created
	GATEWAY_CREATION

	// PHASE2 when gateway(s) is(are) configured
	GATEWAY_CONFIGURATION

	// READY when ready
	READY

	// NETWORKERROR when error
	NETWORKERROR
)
