/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

package hoststate

//go:generate stringer -type=Enum

// Enum represents the state of a host
type Enum int

const (
	Stopped    Enum = iota // Stopped when host is stopped
	Starting               // Starting when host is starting
	Started                // Started when host is started
	Stopping               // Stopping when host is stopping
	Error                  // Error when host is in error state
	Terminated             // Terminated when a host can be enumerated, but it's already deleted
	Unknown                // Unknown when the state is undetermined
	Any                    // Any when a valid state is received
	Failed                 // Failed when installing something on a Started host was not a success
	Deleted                // Deleted when it's not there anymore
)
