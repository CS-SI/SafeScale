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

// Package volumestate defines an enum to represents Volume states life cycle
package volumestate

//go:generate stringer -type=Enum

// Enum represents the state of a host
type Enum int

const (
	// Creating creating The volume is being created
	Creating Enum = iota
	// Available available	The volume is ready to attach to an instance.
	Available
	// Attaching attaching	The volume is attaching to an instance.
	Attaching
	// Detaching detaching	The volume is detaching from an instance.
	Detaching
	// Used in-use The volume is attached to an instance.
	Used
	// Deleting deleting	The volume is being deleted.
	Deleting
	// Error error cases:
	// error	A volume creation error occurred.
	// error_deleting	A volume deletion error occurred.
	// error_backing-up	A backup error occurred.
	// error_restoring	A backup restoration error occurred.
	// error_extending	An error occurred while attempting to extend a volume.
	Error
	// Unknown possible cases
	// backing-up	The volume is being backed up.
	// restoring-backup	A backup is being restored to the volume.
	// downloading	The volume is downloading an image.
	// uploading	The volume is being uploaded to an image.
	// retyping	The volume is changing type to another volume type.
	// extending	The volume is being extended.
	Unknown
)
