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

package abstract

// Default values
const (
	// DefaultUser Default Host user
	DefaultUser = "safescale"

	// DefaultVolumeMountPoint Default mount point for volumes
	DefaultVolumeMountPoint = "/data/"

	// DefaultBucketMountPoint Default mount point for containers
	DefaultBucketMountPoint = "/buckets/"

	// DefaultShareExportedPath Default path to be exported by nfs server
	DefaultShareExportedPath = "/shared/data"

	// DefaultShareMountPath Default path to be mounted to access a nfs directory
	DefaultShareMountPath = "/shared"
)

const (
	SingleHostNetworkCIDR = "10.42.0.0/16"
)
