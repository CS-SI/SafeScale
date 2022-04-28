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

	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/volumespeed"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/observer"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// DISABLED go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/server/resources.Volume -o mocks/mock_volume.go

// Volume links Object Storage folder and getVolumes
type Volume interface {
	Metadata
	data.Identifiable
	observer.Observable
	Consistent

	Attach(ctx context.Context, host Host, path, format string, doNotFormat, doNotMount bool) fail.Error // attaches a volume to a host
	Browse(ctx context.Context, callback func(*abstract.Volume) fail.Error) fail.Error                   // walks through all the metadata objects in network
	Create(ctx context.Context, req abstract.VolumeRequest) fail.Error                                   // creates a volume
	Delete(ctx context.Context) fail.Error                                                               // deletes a volume
	Detach(ctx context.Context, host Host) fail.Error                                                    // detaches the volume identified by ref, ref can be the name or the id
	GetAttachments() (*propertiesv1.VolumeAttachments, fail.Error)                                       // returns the property containing where the volume is attached
	GetSize() (int, fail.Error)                                                                          // returns the size of volume in GB
	GetSpeed() (volumespeed.Enum, fail.Error)                                                            // returns the speed of the volume (more or less the type of hardware)
	ToProtocol(ctx context.Context) (*protocol.VolumeInspectResponse, fail.Error)                        // converts volume to equivalent protocol message
}
