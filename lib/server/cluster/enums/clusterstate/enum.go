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

package clusterstate

//go:generate stringer -type=Enum

// Enum represents the state of a node
type Enum int

const (
	_ Enum = iota
	// Nominal the cluster is started and fully operational
	Nominal
	// Degraded the cluster is running but some key components are failing (typically a master)
	Degraded
	// Stopped the cluster is stopped
	Stopped
	// Initializing the cluster is initializing
	Initializing
	// Created the cluster is ready to be initialized
	Created
	// Creating the cluster is currently created
	Creating
	// Error when an error occurred on gathering cluster state
	Error
	// Removed tells the struct still exist but the underlying cluster has been totally wiped out
	Removed
	// Stopping the cluster is stopping
	Stopping
	// Starting the cluster is starting
	Starting

	// Unknown ...
	Unknown
)
