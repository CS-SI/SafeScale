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

package erbc

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
)

//-------------Utils----------------------------------------------------------------------------------------------------

func (s *StackErbc) CreatePoolIfUnexistant(path string) error {
	panic("implement me")
}

//-------------Volumes Management---------------------------------------------------------------------------------------

// CreateVolume creates a block volume
// - name is the name of the volume
// - size is the size of the volume in GB
// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
func (s *StackErbc) CreateVolume(request resources.VolumeRequest) (*resources.Volume, error) {
	panic("implement me")
}

// GetVolume returns the volume identified by id
func (s *StackErbc) GetVolume(ref string) (*resources.Volume, error) {
	panic("implement me")
}

//ListVolumes return the list of all volume known on the current tenant
func (s *StackErbc) ListVolumes() ([]resources.Volume, error) {
	panic("implement me")
}

// DeleteVolume deletes the volume identified by id
func (s *StackErbc) DeleteVolume(ref string) error {
	panic("implement me")
}

// CreateVolumeAttachment attaches a volume to an host
// - 'name' of the volume attachment
// - 'volume' to attach
// - 'host' on which the volume is attached
func (s *StackErbc) CreateVolumeAttachment(request resources.VolumeAttachmentRequest) (string, error) {
	panic("implement me")
}

// GetVolumeAttachment returns the volume attachment identified by id
func (s *StackErbc) GetVolumeAttachment(serverID, id string) (*resources.VolumeAttachment, error) {
	panic("implement me")
}

// DeleteVolumeAttachment ...
func (s *StackErbc) DeleteVolumeAttachment(serverID, id string) error {
	panic("implement me")
}

// ListVolumeAttachments lists available volume attachment
func (s *StackErbc) ListVolumeAttachments(serverID string) ([]resources.VolumeAttachment, error) {
	panic("implement me")
}
