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

package converters

import (
	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

func BucketMountPointFromResourceToProtocol(in resources.Bucket) (*protocol.BucketMountingPoint, error) {
	if in.IsNull() {
		return nil, scerr.InvalidParameterError("in", "cannot be nil")
	}

	out := &protocol.BucketMountingPoint{
		Bucket: in.SafeGetName(),
		Host:   &protocol.Reference{Name: in.SafeGetHost()},
		Path:   in.SafeGetMountPoint(),
	}
	return out, nil
}

// func VolumeFromResourceToProtocol(task concurrency.Task, in resources.Volume) (*protocol.VolumeInspectResponse, error) {
// 	empty := &protocol.VolumeIspectResponse{}
// 	if in.IsNull() {
// 		return empty, scerr.InvalidParameterError("in", "cannot be null value")
// 	}
// 	if task == nil {
// 		return empty, scerr.InvalidParameterError("task", "cannot be nil")
// 	}

// 	va, err := in.GetAttachments(task)
// 	if err != nil {
// 		return empty, err
// 	}
// 	if len(va.Hosts) == 0 {
// 		return empty, scerr.InconsistentError("failed to find hosts that have mounted the volume")
// 	}
// 	var hostID string
// 	for hostID, _ := range va.Hosts {
// 		break
// 	}

// 	h, err := hostfactory(task, in.SafeGetService(), hostID)
// 	if err != nil {
// 		return empty, err
// 	}
// 	// 1st get volumes attached to the host...
// 	hostVolumes, err := h.GetVolumes(task)
// 	if err != nil {
// 		return empty, err
// 	}
// 	// ... then identify HostVolume struct associated to volume...
// 	hostVolume, ok := hostVolumes.VolumeByID[in.SafeGetID()]
// 	if !ok {
// 		return empty, scerr.InconsistentError("failed to find device where volume '%s' is attached on host '%s'", in.SafeGetName(), h.SafeGetName())
// 	}
// 	// ... then get mounts on the host...
// 	hostMounts, err := h.GetMounts(task)
// 	if err != nil {
// 		return empty, err
// 	}
// 	// ... and identify the HostMount struct corresponding to the mounted volume
// 	hostMount, ok := hostMounts.LocalMountsByDevice[hostVolume.Device]
// 	if !ok {
// 		return empty, scerr.InconsistentError("failed to find where volume '%s' is mounted on host '%s'", in.SafeGetName(), h.SafeGetName())
// 	}

// 	// For now, volume is attachable only to one host...
// 	a := &protocol.VolumeAttachment{
// 		Host:      &protocol.Reference{ID: hostID},
// 		MountPath: hostMount.Path,
// 		Format:    hostMount.FileSystem,
// 		Device:    hostMmount.Device,
// 	}
// 	out := &protocol.VolumeInspectResponse{
// 		Id:          in.SafeGetID(),
// 		Name:        in.SafeGetName(),
// 		Speed:       in.SafeGetSpeed(task),
// 		Size:        in.SafeGetSize(task),
// 		Attachments: &protocol.VolumeAttachment{a},
// 	}
// 	return out, nil
// }
