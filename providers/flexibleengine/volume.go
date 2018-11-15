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

package flexibleengine

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	gc "github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/blockstorage/v1/volumes"
	v2_vol "github.com/gophercloud/gophercloud/openstack/blockstorage/v2/volumes"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/volumeattach"

	"github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeProperty"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeState"
	propsv1 "github.com/CS-SI/SafeScale/providers/model/properties/v1"
	"github.com/CS-SI/SafeScale/providers/openstack"
)

// DeleteVolume deletes the volume identified by id
// This code seems to be the same than openstack provider, but for now it HAS TO BE DUPLICATED
// because of use of metadata (ObjectStorage uses Swift for openstack, S3 for flexibleengine).
// TODO: remove metadata from providers code
func (client *Client) DeleteVolume(id string) error {
	mv, err := metadata.LoadVolume(client, id)
	if err != nil {
		log.Debugf("Error deleting volume '%s': failed loading metadata: %+v", id, err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting volume '%s': volume metadata not found", id))
	}
	if mv == nil {
		log.Debugf("Error deleting volume '%s': volume not found", id)
		return model.ResourceNotFoundError("volume", id)
	}
	volume := mv.Get()

	r := volumes.Delete(client.osclt.Volume, id)
	err = r.ExtractErr()
	if err != nil {
		switch r.Err.(type) {
		case gc.ErrDefault400:
			badRequest := openstack.ParseBadRequest(r.Err.Error())
			spew.Dump(badRequest)
			if badRequest != nil {
				spew.Dump(badRequest)
				msg := fmt.Sprintf("Error creating volume '%s': %s\n", volume.Name, badRequest["message"])
				log.Debugf(msg)
				return fmt.Errorf(msg)
			}
		}
		log.Debugf("Error deleting volume '%s': %+v", volume.Name, err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting volume '%s': %s", volume.Name, openstack.ProviderErrorToString(err)))
	}
	err = metadata.RemoveVolume(client, id)
	if err != nil {
		log.Debugf("Error deleting volume '%s': failed to update metadata: %+v", volume.Name, err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting volume '%s': %s", volume.Name, openstack.ProviderErrorToString(err)))
	}
	return nil
}

// toVolumeState converts a Volume status returned by the OpenStack driver into VolumeState enum
func toVolumeState(status string) VolumeState.Enum {
	switch status {
	case "creating":
		return VolumeState.CREATING
	case "available":
		return VolumeState.AVAILABLE
	case "attaching":
		return VolumeState.ATTACHING
	case "detaching":
		return VolumeState.DETACHING
	case "in-use":
		return VolumeState.USED
	case "deleting":
		return VolumeState.DELETING
	case "error", "error_deleting", "error_backing-up", "error_restoring", "error_extending":
		return VolumeState.ERROR
	default:
		return VolumeState.OTHER
	}
}

func (client *Client) getVolumeType(speed VolumeSpeed.Enum) string {
	for t, s := range client.osclt.Cfg.VolumeSpeeds {
		if s == speed {
			return t
		}
	}
	switch speed {
	case VolumeSpeed.SSD:
		return client.getVolumeType(VolumeSpeed.HDD)
	case VolumeSpeed.HDD:
		return client.getVolumeType(VolumeSpeed.COLD)
	default:
		return ""
	}
}

func (client *Client) getVolumeSpeed(vType string) VolumeSpeed.Enum {
	speed, ok := client.osclt.Cfg.VolumeSpeeds[vType]
	if ok {
		return speed
	}
	return VolumeSpeed.HDD
}

// CreateVolume creates a block volume
func (client *Client) CreateVolume(request model.VolumeRequest) (*model.Volume, error) {
	vol, err := client.ExCreateVolume(request, "")

	err = metadata.SaveVolume(client, vol)
	if err != nil {
		nerr := client.DeleteVolume(vol.ID)
		if nerr != nil {
			log.Warnf("Error deleting volume: %v", nerr)
		}
		return nil, fmt.Errorf("failed to create Volume: %s", openstack.ProviderErrorToString(err))
	}

	return vol, err
}

// ExCreateVolume creates a block volume
func (client *Client) ExCreateVolume(request model.VolumeRequest, imageID string) (*model.Volume, error) {
	// Check if a volume already exists with the same name
	volume, err := metadata.LoadVolume(client, request.Name)
	if err != nil {
		return nil, err
	}
	if volume != nil {
		return nil, model.ResourceAlreadyExistsError("Volume", request.Name)
	}

	opts := v2_vol.CreateOpts{
		Name:       request.Name,
		Size:       request.Size,
		VolumeType: client.getVolumeType(request.Speed),
		ImageID:    imageID,
	}
	vol, err := v2_vol.Create(client.osclt.Volume, opts).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error creating volume : %s", openstack.ProviderErrorToString(err))
	}
	v := model.Volume{
		ID:    vol.ID,
		Name:  vol.Name,
		Size:  vol.Size,
		Speed: client.getVolumeSpeed(vol.VolumeType),
		State: toVolumeState(vol.Status),
	}
	return &v, nil
}

// GetVolume returns the volume identified by id
func (client *Client) GetVolume(id string) (*model.Volume, error) {
	return client.osclt.GetVolume(id)
}

// ListVolumes list available volumes
func (client *Client) ListVolumes(all bool) ([]model.Volume, error) {
	if all {
		return client.osclt.ListVolumes(all)
	}
	return client.listMonitoredVolumes()
}

// listMonitoredVolumes lists available volumes created by SafeScale (ie registered in object storage)
// This code seems to be the same than openstack provider, but for now it HAS TO BE DUPLICATED
// because of use of metadata (ObjectStorage uses Swift for openstack, S3 for flexibleengine).
// TODO: remove metadata from providers code
func (client *Client) listMonitoredVolumes() ([]model.Volume, error) {
	var vols []model.Volume
	m := metadata.NewVolume(client)
	err := m.Browse(func(vol *model.Volume) error {
		vols = append(vols, *vol)
		return nil
	})
	if err != nil {
		log.Debugf("Error listing monitored volumes: browsing volumes: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error listing volumes : %s", openstack.ProviderErrorToString(err)))
	}
	return vols, nil
}

// CreateVolumeAttachment attaches a volume to an host
// This code seems to be the same than openstack provider, but for now it HAS TO BE DUPLICATED
// because of use of metadata (ObjectStorage uses Swift for openstack, S3 for flexibleengine).
// TODO: remove metadata from providers code
func (client *Client) CreateVolumeAttachment(request model.VolumeAttachmentRequest) (string, error) {
	// Ensure volume and host are known
	mv, err := metadata.LoadVolume(client, request.VolumeID)
	if err != nil {
		return "", err
	}
	if mv == nil {
		return "", errors.Wrap(model.ResourceNotFoundError("volume", request.VolumeID), "Cannot create volume attachment")
	}
	volume := mv.Get()

	vpAttachedV1 := propsv1.BlankVolumeAttachments
	err = volume.Properties.Get(VolumeProperty.AttachedV1, &vpAttachedV1)
	if err != nil {
		return "", err
	}
	if len(vpAttachedV1.HostIDs) == 1 {
		// For now, allows only one attachment...
		return "", fmt.Errorf("Volume '%s' already attached to host(s)", request.VolumeID)
	}

	// Loads host
	mh, err := metadata.LoadHost(client, request.HostID)
	if err != nil {
		return "", err
	}
	if mh == nil {
		return "", errors.Wrap(model.ResourceNotFoundError("host", request.HostID), "Cannot create volume attachment")
	}

	// Creates the attachment
	r := volumeattach.Create(client.osclt.Compute, request.HostID, volumeattach.CreateOpts{
		VolumeID: request.VolumeID,
	})
	va, err := r.Extract()
	if err != nil {
		spew.Dump(r.Err)
		// switch r.Err.(type) {
		// 	case
		// }
		// message := extractMessageFromBadRequest(r.Err)
		// if message != ""
		log.Debugf("Error creating volume attachment: actual attachment creation: %+v", err)
		return "", errors.Wrap(err, fmt.Sprintf("Error creating volume attachment between server %s and volume %s: %s", request.HostID, request.VolumeID, openstack.ProviderErrorToString(err)))
	}

	return va.ID, nil
}

// GetVolumeAttachment returns the volume attachment identified by id
func (client *Client) GetVolumeAttachment(serverID, id string) (*model.VolumeAttachment, error) {
	return client.osclt.GetVolumeAttachment(serverID, id)
}

// ListVolumeAttachments lists available volume attachment
func (client *Client) ListVolumeAttachments(serverID string) ([]model.VolumeAttachment, error) {
	return client.osclt.ListVolumeAttachments(serverID)
}

// DeleteVolumeAttachment deletes the volume attachment identifed by id
// This code seems to be the same than openstack provider, but for now it HAS TO BE DUPLICATED
// because of use of metadata (ObjectStorage uses Swift for openstack, S3 for flexibleengine).
// TODO: remove metadata from providers code
func (client *Client) DeleteVolumeAttachment(serverID, id string) error {
	va, err := client.GetVolumeAttachment(serverID, id)
	if err != nil {
		log.Debugf("Error deleting volume attachment: getting attachments: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting volume attachment %s: %s", id, openstack.ProviderErrorToString(err)))
	}

	r := volumeattach.Delete(client.osclt.Compute, serverID, id)
	err = r.ExtractErr()
	if err != nil {
		log.Debugf("Error deleting volume attachment: deleting attachments: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting volume attachment %s: %s", id, openstack.ProviderErrorToString(err)))
	}

	mtdVol, err := metadata.LoadVolume(client, id)
	if err != nil {
		log.Debugf("Error deleting volume attachment: loading metadata: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting volume attachment %s: %s", id, openstack.ProviderErrorToString(err)))
	}

	err = mtdVol.Detach(va)
	if err != nil {
		log.Debugf("Error deleting volume attachment: detaching volume: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting volume attachment %s: %s", id, openstack.ProviderErrorToString(err)))
	}

	return nil
}
