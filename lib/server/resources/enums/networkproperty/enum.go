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

package networkproperty

// Enum represents the type of networkproperty
type Enum string

const (
	DescriptionV1    = "1" // contains optional additional info describing Networking (purpose, ...)
	HostsV1          = "2" // OBSOLETE: moved to subnetproperty: contains list of hosts attached to the network
	SubnetsV1        = "3" // contains the subnets created in the Network
	SingleHostsV1    = "4" // contains the CIDRs usable for single Hosts
	SecurityGroupsV1 = "5" // contains the Security Groups owned by the Network
)
