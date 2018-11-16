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

package HostProperty

const (
	// DescriptionV1 contains (optional) additional info describing host (purpose, ...)
	DescriptionV1 = "1"
	// NetworkV1 contains additional info about the network of the host
	NetworkV1 = "2"
	// SizingV1 contains additional info about the sizing of the host
	SizingV1 = "3"
	// FeaturesV1 contains optional additional info describing installed features on a host
	FeaturesV1 = "4"
	// VolumesV1 contains optional additional info about attached volumes on the host
	VolumesV1 = "5"
	// SharesV1 contains optional additional info about Nas role of the host
	SharesV1 = "6"
	// MountsV1 contains optional additional info about mounted devices (locally attached or remote filesystem)
	MountsV1 = "7"
)
