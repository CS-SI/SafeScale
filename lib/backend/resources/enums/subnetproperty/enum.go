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

package subnetproperty

// Enum represents the type of subnetproperty
type Enum string

const (
	// DescriptionV1 contains optional additional info describing host (purpose, ...)
	DescriptionV1 = "1"
	// HostsV1 contains list of hosts attached to the network
	HostsV1 = "2"
	// SecurityGroupsV1 contains optional additional information about security groups binded to the host
	SecurityGroupsV1 = "3"
)
