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

package ExitCode

//go:generate stringer -type=Enum

// Enum ...
type Enum int

const (
	// OK (=0) is returned when everything is ok
	OK Enum = iota
	// Run ...
	Run
	// InvalidArgument is returned on invalid argument
	InvalidArgument
	// InvalidOption is returned on invalid option
	InvalidOption
	// NotFound is returned when resource is not found
	NotFound
	// Timeout is returned when something timed out
	Timeout
	// RPC is returned when an RPC call fails
	RPC
	// NotApplicable is returned when the command cannot be honored in the context
	NotApplicable
	// Duplicate is returned when resource already exists
	Duplicate
	// NotImplemented is returned when a function is not yet implemented
	NotImplemented

	// NextExitCode is the next error code usable
	NextExitCode
)
