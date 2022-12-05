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

package ovhtf

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	designVolumeResourceSnippetPath = "snippets/resource_volume_design.tf"
)

func (p *provider) CreateVolume(ctx context.Context, request abstract.VolumeRequest) (*abstract.Volume, fail.Error) {
	// TODO implement me
	panic("implement me")
}

func (p *provider) InspectVolume(ctx context.Context, id string) (*abstract.Volume, fail.Error) {
	// TODO implement me
	panic("implement me")
}

func (p *provider) ListVolumes(ctx context.Context) ([]*abstract.Volume, fail.Error) {
	// TODO implement me
	panic("implement me")
}

func (p *provider) DeleteVolume(ctx context.Context, id string) fail.Error {
	// TODO implement me
	panic("implement me")
}

func (p *provider) CreateVolumeAttachment(ctx context.Context, request abstract.VolumeAttachmentRequest) (string, fail.Error) {
	// TODO implement me
	panic("implement me")
}

func (p *provider) InspectVolumeAttachment(ctx context.Context, serverID, id string) (*abstract.VolumeAttachment, fail.Error) {
	// TODO implement me
	panic("implement me")
}

func (p *provider) ListVolumeAttachments(ctx context.Context, serverID string) ([]*abstract.VolumeAttachment, fail.Error) {
	// TODO implement me
	panic("implement me")
}

func (p *provider) DeleteVolumeAttachment(ctx context.Context, serverID, id string) fail.Error {
	// TODO implement me
	panic("implement me")
}

func (p *provider) ConsolidateVolumeSnippet(av *abstract.Volume) {
	if valid.IsNil(p) || av == nil {
		return
	}

	_ = av.AddOptions(abstract.UseTerraformSnippet(designVolumeResourceSnippetPath))
}