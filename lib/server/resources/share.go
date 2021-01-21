/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/lib/protocol"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// Share contains information to maintain in Object Storage a list of shared folders
type Share interface {
	Metadata
	data.Identifiable
	data.NullValue

	Browse(task concurrency.Task, callback func(hostName string, shareID string) fail.Error) fail.Error
	Create(task concurrency.Task, shareName string, host Host, path string, options string /*securityModes []string, readOnly, rootSquash, secure, async, noHide, crossMount, subtreeCheck bool*/) fail.Error // creates a share on host
	GetServer(task concurrency.Task) (Host, fail.Error)                                                                                                                                                       // returns the *Host acting as share server, with error handling
	Mount(task concurrency.Task, host Host, path string, withCache bool) (*propertiesv1.HostRemoteMount, fail.Error)                                                                                          // mounts a share on a local directory of an host
	Unmount(task concurrency.Task, host Host) fail.Error                                                                                                                                                      // unmounts a share from local directory of an host
	ToProtocol(task concurrency.Task) (*protocol.ShareMountList, fail.Error)
}
