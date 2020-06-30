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
	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// Volume links Object Storage folder and getVolumes
type Volume interface {
	Metadata
	data.Identifiable
	data.NullValue

	Attach(task concurrency.Task, host Host, path, format string, doNotFormat bool) fail.Error // attaches a volume to an host
	Browse(task concurrency.Task, callback func(*abstract.Volume) fail.Error) fail.Error       // walks through all the metadata objects in network
	Create(task concurrency.Task, req abstract.VolumeRequest) fail.Error                       // creates a volume
	Detach(task concurrency.Task, host Host) fail.Error                                        // detaches the volume identified by ref, ref can be the name or the id
	GetAttachments(task concurrency.Task) (*propertiesv1.VolumeAttachments, fail.Error)        // returns the property containing where the volume is attached
	GetSize(task concurrency.Task) (int, fail.Error)                                           // returns the size of volume in GB
	GetSpeed(task concurrency.Task) (volumespeed.Enum, fail.Error)                             // returns the speed of the volume (more or less the type of hardware)
	ToProtocol(task concurrency.Task) (*protocol.VolumeInspectResponse, fail.Error)            // converts volume to equivalent protocol message
}
