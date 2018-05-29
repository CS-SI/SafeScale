package Complexity
/*
* Copyright 2015-2018, CS Systemes d'Information, http://www.c-s.fr
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

//go:generate stringer -type=Enum

//Enum represents the complexity of a cluster
type Enum int

const (

	//Simple is the simplest mode of cluster
	Simple Enum = iota
	//HighAvailability allows the cluster to be resistant to 1 master failure
	HighAvailability
	//HighVolume allows the cluster to be resistant to 2 master failures and is sized for high volume of agents
	HighVolume
)
