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

package resources

import (
	"context"

	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/backend/resources.Share -o mocks/mock_share.go

// Share contains information to maintain in Object Storage a list of shared folders
type Share interface {
	Metadata
	data.Identifiable
	Consistent

	Browse(ctx context.Context, callback func(hostName string, shareID string) fail.Error) fail.Error
	Create(ctx context.Context, shareName string, host Host, path string, options string /*securityModes []string, readOnly, rootSquash, secure, async, noHide, crossMount, subtreeCheck bool*/) fail.Error // creates a share on host
	Delete(ctx context.Context) fail.Error
	GetServer(ctx context.Context) (Host, fail.Error)                                                              // returns the *Host acting as share server, with error handling
	Mount(ctx context.Context, host Host, path string, withCache bool) (*propertiesv1.HostRemoteMount, fail.Error) // mounts a share on a local directory of a host
	Unmount(ctx context.Context, host Host) fail.Error                                                             // unmounts a share from local directory of a host
	ToProtocol(ctx context.Context) (*protocol.ShareMountList, fail.Error)
}
