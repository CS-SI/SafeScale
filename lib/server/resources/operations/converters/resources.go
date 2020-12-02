/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

package converters

import (
	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// BucketMountPointFromResourceToProtocol converts a bucket mount point from resource to protocol
func BucketMountPointFromResourceToProtocol(task concurrency.Task, in resources.Bucket) (*protocol.BucketMountingPoint, fail.Error) {
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if in.IsNull() {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}

	host, xerr := in.GetHost(task)
	if xerr != nil {
		return nil, xerr
	}
	path, err := in.GetMountPoint(task)
	if err != nil {
		return nil, err
	}
	out := &protocol.BucketMountingPoint{
		Bucket: in.GetName(),
		Host:   &protocol.Reference{Name: host},
		Path:   path,
	}
	return out, nil
}

// func VolumeFromResourceToProtocol(task concurrency.Task, in resources.Volume) (*protocol.VolumeInspectResponse, error) {
// 	empty := &protocol.VolumeIspectResponse{}
// 	if in.IsNull() {
// 		return empty, fail.InvalidParameterError("in", "cannot be null value")
// 	}
// 	if task.IsNull() {
// 		return empty, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
// 	}

// 	va, err := in.GetAttachments(task)
// 	if err != nil {
// 		return empty, err
// 	}
// 	if len(va.Hosts) == 0 {
// 		return empty, fail.InconsistentError("failed to find hosts that have mounted the volume")
// 	}
// 	var hostID string
// 	for hostID, _ := range va.Hosts {
// 		break
// 	}

// 	h, err := hostfactory(task, in.GetService(), hostID)
// 	if err != nil {
// 		return empty, err
// 	}
// 	// 1st get volumes attached to the host...
// 	hostVolumes, err := h.GetVolumes(task)
// 	if err != nil {
// 		return empty, err
// 	}
// 	// ... then identify HostVolume struct associated to volume...
// 	hostVolume, ok := hostVolumes.VolumeByID[in.GetID()]
// 	if !ok {
// 		return empty, fail.InconsistentError("failed to find device where volume '%s' is attached on host '%s'", in.GetName(), h.GetName())
// 	}
// 	// ... then get mounts on the host...
// 	hostMounts, err := h.GetMounts(task)
// 	if err != nil {
// 		return empty, err
// 	}
// 	// ... and identify the HostMount struct corresponding to the mounted volume
// 	hostMount, ok := hostMounts.LocalMountsByDevice[hostVolume.Device]
// 	if !ok {
// 		return empty, fail.InconsistentError("failed to find where volume '%s' is mounted on host '%s'", in.GetName(), h.GetName())
// 	}

// 	// For now, volume is attachable only to one host...
// 	a := &protocol.VolumeAttachment{
// 		IPAddress:      &protocol.Reference{GetID: hostID},
// 		MountPath: hostMount.Path,
// 		Format:    hostMount.FileSystem,
// 		Device:    hostMmount.Device,
// 	}
// 	out := &protocol.VolumeInspectResponse{
// 		Id:          in.GetID(),
// 		GetName:        in.GetName(),
// 		getSpeed:       in.getSpeed(task),
// 		getSize:        in.getSize(task),
// 		Attachments: &protocol.VolumeAttachment{a},
// 	}
// 	return out, nil
// }
