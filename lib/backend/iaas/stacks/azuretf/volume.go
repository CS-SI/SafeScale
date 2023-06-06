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

package azuretf

import (
	"context"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// -------------Volumes Management---------------------------------------------------------------------------------------

// CreateVolume creates a block volume
// - name is the name of the volume
// - size is the size of the volume in GB
// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
func (s stack) CreateVolume(ctx context.Context, request abstract.VolumeRequest) (_ *abstract.Volume, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	return nil, fail.NotImplementedError("implement me")
}

// InspectVolume returns the volume identified by id
func (s stack) InspectVolume(ctx context.Context, ref string) (_ *abstract.Volume, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	return nil, fail.NotImplementedError("implement me")
}

// ListVolumes return the list of all volume known on the current tenant
func (s stack) ListVolumes(ctx context.Context) ([]*abstract.Volume, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	return nil, fail.NotImplementedError("implement me")
}

// DeleteVolume deletes the volume identified by id
func (s stack) DeleteVolume(ctx context.Context, ref string) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	return fail.NotImplementedError("implement me")
}

// CreateVolumeAttachment attaches a volume to a host
func (s stack) CreateVolumeAttachment(ctx context.Context, request abstract.VolumeAttachmentRequest) (string, fail.Error) {
	if valid.IsNil(s) {
		return "", fail.InvalidInstanceError()
	}
	return "", fail.NotImplementedError("implement me")
}

// InspectVolumeAttachment returns the volume attachment identified by id
func (s stack) InspectVolumeAttachment(ctx context.Context, hostRef, vaID string) (*abstract.VolumeAttachment, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	return nil, fail.NotImplementedError("implement me")
}

// DeleteVolumeAttachment ...
func (s stack) DeleteVolumeAttachment(ctx context.Context, serverRef, vaID string) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	return fail.NotImplementedError("implement me")
}

// ListVolumeAttachments lists available volume attachment
func (s stack) ListVolumeAttachments(ctx context.Context, serverRef string) ([]*abstract.VolumeAttachment, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	return nil, fail.NotImplementedError("implement me")
}
