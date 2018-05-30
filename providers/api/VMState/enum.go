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

package VMState

//go:generate stringer -type=Enum

//Enum represents the state of a VM
type Enum int

const (
	/*STOPPED VM is stopped*/
	STOPPED Enum = iota
	/*STARTING VM is starting*/
	STARTING
	/*STARTED VM is started*/
	STARTED
	/*STOPPING VM is stopping*/
	STOPPING
	/*ERROR VM is in error state*/
	ERROR
)
