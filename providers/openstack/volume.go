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

package openstack

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/gophercloud/gophercloud/openstack/blockstorage/v1/volumes"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/volumeattach"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeProperty"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeState"
	propsv1 "github.com/CS-SI/SafeScale/providers/model/properties/v1"
)

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
	for t, s := range client.Cfg.VolumeSpeeds {
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
	speed, ok := client.Cfg.VolumeSpeeds[vType]
	if ok {
		return speed
	}
	return VolumeSpeed.HDD
}

// CreateVolume creates a block volume
// - name is the name of the volume
// - size is the size of the volume in GB
// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
func (client *Client) CreateVolume(request model.VolumeRequest) (*model.Volume, error) {
	// Check if a volume already exists with the same name
	volume, err := metadata.LoadVolume(client, request.Name)
	if err != nil {
		log.Debugf("Error creating volume, loading volume metadata: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error creating volume, loading volume metadata"))
	}
	if volume != nil {
		log.Debugf("Error creating volume, volume not found: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Volume '%s' already exists", request.Name))
	}

	vol, err := volumes.Create(client.Volume, volumes.CreateOpts{
		Name:       request.Name,
		Size:       request.Size,
		VolumeType: client.getVolumeType(request.Speed),
	}).Extract()
	if err != nil {
		log.Debugf("Error creating volume: volume creation invocation: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error creating volume : %s", ProviderErrorToString(err)))
	}
	v := model.Volume{
		ID:    vol.ID,
		Name:  vol.Name,
		Size:  vol.Size,
		Speed: client.getVolumeSpeed(vol.VolumeType),
		State: toVolumeState(vol.Status),
	}
	err = metadata.SaveVolume(client, &v)
	if err != nil {
		nerr := client.DeleteVolume(v.ID)
		if nerr != nil {
			log.Warnf("Error deleting volume: %v", nerr)
		}
		log.Debugf("Error creating volume: saving volume metadata: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error creating volume : %s", ProviderErrorToString(err)))
	}

	return &v, nil
}

// GetVolume returns the volume identified by id
func (client *Client) GetVolume(id string) (*model.Volume, error) {
	vol, err := volumes.Get(client.Volume, id).Extract()
	if err != nil {
		log.Debugf("Error getting volume: getting volume invocation: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting volume: %s", ProviderErrorToString(err)))
	}
	av := model.Volume{
		ID:    vol.ID,
		Name:  vol.Name,
		Size:  vol.Size,
		Speed: client.getVolumeSpeed(vol.VolumeType),
		State: toVolumeState(vol.Status),
	}
	return &av, nil
}

// ListVolumes return the list of all volume known on the current tenant (all=ture)
//or 'only' thode monitored by safescale (all=false) ie those monitored by metadata
func (client *Client) ListVolumes(all bool) ([]model.Volume, error) {
	if all {
		return client.listAllVolumes()
	}
	return client.listMonitoredVolumes()

}

// listAllVolumes list available volumes
func (client *Client) listAllVolumes() ([]model.Volume, error) {
	var vs []model.Volume
	err := volumes.List(client.Volume, volumes.ListOpts{}).EachPage(func(page pagination.Page) (bool, error) {
		list, err := volumes.ExtractVolumes(page)
		if err != nil {
			log.Errorf("Error listing volumes: volume extraction: %+v", err)
			return false, err
		}
		for _, vol := range list {
			av := model.Volume{
				ID:    vol.ID,
				Name:  vol.Name,
				Size:  vol.Size,
				Speed: client.getVolumeSpeed(vol.VolumeType),
				State: toVolumeState(vol.Status),
			}
			vs = append(vs, av)
		}
		return true, nil
	})
	if err != nil || len(vs) == 0 {
		if err != nil {
			log.Debugf("Error listing volumes: list invocation: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf("Error listing volume types: %s", ProviderErrorToString(err)))
		}
		log.Warnf("Complete volume list empty")
	}
	return vs, nil
}

// listMonitoredVolumes lists available Volumes created by SafeScale (ie registered in object storage)
func (client *Client) listMonitoredVolumes() ([]model.Volume, error) {
	var vols []model.Volume
	m := metadata.NewVolume(client)
	err := m.Browse(func(vol *model.Volume) error {
		vols = append(vols, *vol)
		return nil
	})
	if err != nil {
		log.Debugf("Error listing monitored volumes: browsing volumes: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error listing volumes : %s", ProviderErrorToString(err)))
	}
	return vols, nil
}

// DeleteVolume deletes the volume identified by id
func (client *Client) DeleteVolume(id string) error {
	volume, err := metadata.LoadVolume(client, id)
	if err != nil {
		log.Debugf("Error deleting volume: loading metadata: %+v", err)
		return errors.Wrap(err, "Error deleting volume: loading metadata")
	}
	if volume == nil {
		log.Debugf("Error deleting volume: volume not found: %+v", err)
		return model.ResourceNotFoundError("volume", id)
	}

	r := volumes.Delete(client.Volume, id)
	err = r.ExtractErr()
	if err != nil {
		spew.Dump(r.Err)
		log.Debugf("Error deleting volume: actual delete call: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting volume: %s", ProviderErrorToString(err)))
	}
	err = metadata.RemoveVolume(client, id)
	if err != nil {
		log.Debugf("Error deleting volume: removing volume metadata: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting volume: %s", ProviderErrorToString(err)))
	}
	return nil
}

// CreateVolumeAttachment attaches a volume to an host
// - 'name' of the volume attachment
// - 'volume' to attach
// - 'host' on which the volume is attached
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
	r := volumeattach.Create(client.Compute, request.HostID, volumeattach.CreateOpts{
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
		return "", errors.Wrap(err, fmt.Sprintf("Error creating volume attachment between server %s and volume %s: %s", request.HostID, request.VolumeID, ProviderErrorToString(err)))
	}

	return va.ID, nil
}

// GetVolumeAttachment returns the volume attachment identified by id
func (client *Client) GetVolumeAttachment(serverID, id string) (*model.VolumeAttachment, error) {
	va, err := volumeattach.Get(client.Compute, serverID, id).Extract()
	if err != nil {
		log.Debugf("Error getting volume attachment: get call: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting volume attachment %s: %s", id, ProviderErrorToString(err)))
	}
	return &model.VolumeAttachment{
		ID:       va.ID,
		ServerID: va.ServerID,
		VolumeID: va.VolumeID,
		Device:   va.Device,
	}, nil
}

// ListVolumeAttachments lists available volume attachment
func (client *Client) ListVolumeAttachments(serverID string) ([]model.VolumeAttachment, error) {
	var vs []model.VolumeAttachment
	err := volumeattach.List(client.Compute, serverID).EachPage(func(page pagination.Page) (bool, error) {
		list, err := volumeattach.ExtractVolumeAttachments(page)
		if err != nil {
			log.Debugf("Error listing volume attachment: extracting attachments: %+v", err)
			return false, errors.Wrap(err, "Error listing volume attachment: extracting attachments")
		}
		for _, va := range list {
			ava := model.VolumeAttachment{
				ID:       va.ID,
				ServerID: va.ServerID,
				VolumeID: va.VolumeID,
				Device:   va.Device,
			}
			vs = append(vs, ava)
		}
		return true, nil
	})
	if err != nil {
		log.Debugf("Error listing volume attachment: listing attachments: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error listing volume types: %s", ProviderErrorToString(err)))
	}
	return vs, nil
}

// DeleteVolumeAttachment deletes the volume attachment identifed by id
func (client *Client) DeleteVolumeAttachment(serverID, id string) error {
	va, err := client.GetVolumeAttachment(serverID, id)
	if err != nil {
		log.Debugf("Error deleting volume attachment: getting attachments: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting volume attachment %s: %s", id, ProviderErrorToString(err)))
	}

	err = volumeattach.Delete(client.Compute, serverID, id).ExtractErr()
	if err != nil {
		log.Debugf("Error deleting volume attachment: deleting attachments: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting volume attachment %s: %s", id, ProviderErrorToString(err)))
	}

	mtdVol, err := metadata.LoadVolume(client, id)
	if err != nil {
		log.Debugf("Error deleting volume attachment: loading metadata: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting volume attachment %s: %s", id, ProviderErrorToString(err)))
	}

	err = mtdVol.Detach(va)
	if err != nil {
		log.Debugf("Error deleting volume attachment: detaching volume: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting volume attachment %s: %s", id, ProviderErrorToString(err)))
	}

	return nil
}
