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

package HostState

//go:generate stringer -type=Enum

//Enum represents the state of an host
type Enum int

const (
	// STOPPED when host is stopped
	STOPPED Enum = iota
	// STARTING when host is starting
	STARTING
	// STARTED when host is started
	STARTED
	// STOPPING when host is stopping
	STOPPING
	// ERROR when host is in error state*/
	ERROR
)
