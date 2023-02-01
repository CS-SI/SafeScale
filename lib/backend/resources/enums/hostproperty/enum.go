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

package hostproperty

const (
	DescriptionV1       = "1"  // (optional) additional info describing host (purpose, ...)
	NetworkV1           = "2"  // DEPRECATED: deprecated additional info about the network of the host
	SizingV1            = "3"  // DEPRECATED: deprecated optional additional info about the sizing of the host
	FeaturesV1          = "4"  // optional additional info describing installed features on a host
	VolumesV1           = "5"  // optional additional info about attached volumes on the host
	SharesV1            = "6"  // optional additional info about Nas role of the host
	MountsV1            = "7"  // optional additional info about mounted devices (locally attached or remote filesystem)
	SystemV1            = "8"  // optional additional info about system
	SizingV2            = "9"  // optional additional info about the sizing of the host
	ClusterMembershipV1 = "10" // optional additional information about the cluster membership of the host
	SecurityGroupsV1    = "11" // optional additional information about security groups binded to the host
	NetworkV2           = "12" // optional additional information about network of the host
	LabelsV1            = "13" // optional additional info about tags (ie labels without value) on the host
)
