/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package resources

import (
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
)

// Share contains information to maintain in Object Storage a list of shared folders
type Share interface {
	Metadata
	data.Identifyable

	Browse(task concurrency.Task, callback func(hostName string, shareID string) error) error
	// Create creates a share on host
	Create(task concurrency.Task, shareName string, host Host, path string, securityModes []string, readOnly, rootSquash, secure, async, noHide, crossMount, subtreeCheck bool) error
	// Server returns the *Host acting as share server
	Server(task concurrency.Task) (Host, error)
	// Mount mounts a share on a local directory of an host
	Mount(task concurrency.Task, hostName, path string, withCache bool) (*propertiesv1.HostRemoteMount, error)
	// Unmount unmounts a share from local directory of an host
	Unmount(task concurrency.Task, targetName string) error
}
