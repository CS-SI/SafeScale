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
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	gc "github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/blockstorage/v1/volumes"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/volumeattach"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeState"
	"github.com/CS-SI/SafeScale/utils/retry"
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

func (s *Stack) getVolumeType(speed VolumeSpeed.Enum) string {
	if s == nil {
		panic("Calling s.getVolumeType with s==nil!")
	}

	for t, s := range s.Cfg.VolumeSpeeds {
		if s == speed {
			return t
		}
	}
	switch speed {
	case VolumeSpeed.SSD:
		return s.getVolumeType(VolumeSpeed.HDD)
	case VolumeSpeed.HDD:
		return s.getVolumeType(VolumeSpeed.COLD)
	default:
		return ""
	}
}

func (s *Stack) getVolumeSpeed(vType string) VolumeSpeed.Enum {
	if s == nil {
		panic("Calling s.getVolumeSpeed with s==nil!")
	}

	speed, ok := s.Cfg.VolumeSpeeds[vType]
	if ok {
		return speed
	}
	return VolumeSpeed.HDD
}

// CreateVolume creates a block volume
// - name is the name of the volume
// - size is the size of the volume in GB
// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
func (s *Stack) CreateVolume(request model.VolumeRequest) (*model.Volume, error) {
	log.Debugf("openstack.Stack.CreateVolume(%s) called", request.Name)
	defer log.Debugf("openstack.Stack.CreateVolume(%s) done", request.Name)

	if s == nil {
		panic("Calling s.CreateVolume with s==nil!")
	}

	volume, err := client.GetVolume(request.Name)
	if err != nil {
		if _, ok := err.(model.ErrResourceNotFound); !ok {
			return nil, err
		}
	}
	if volume != nil {
		return nil, fmt.Errorf("volume '%s' already exists", request.Name)
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
	return &v, nil
}

// GetVolume returns the volume identified by id
func (s *Stack) GetVolume(id string) (*model.Volume, error) {
	log.Debugf("openstack.Stack.GetVolume(%s) called", id)
	defer log.Debugf("openstack.Stack.GetVolume(%s) done", id)

	if s == nil {
		panic("Calling s.GetVolume with s==nil!")
	}

	r := volumes.Get(client.Volume, id)
	volume, err := r.Extract()
	if err != nil {
		log.Debugf("Error getting volume: getting volume invocation: %+v", err)
		switch err.(type) {
		case gc.ErrDefault404:
			return nil, model.ResourceNotFoundError("volume", id)
		}
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting volume: %s", ProviderErrorToString(err)))
	}

	av := model.Volume{
		ID:    volume.ID,
		Name:  volume.Name,
		Size:  volume.Size,
		Speed: s.getVolumeSpeed(volume.VolumeType),
		State: toVolumeState(volume.Status),
	}
	return &av, nil
}

// ListVolumes returns the list of all volumes known on the current tenant
func (s *Stack) ListVolumes() ([]model.Volume, error) {
	log.Debug("openstack.Stack.ListVolumes() called")
	defer log.Debug("openstack.Stack.ListVolumes() done")

	if s == nil {
		panic("Calling s.ListVolumes with s==nil!")
	}

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

// DeleteVolume deletes the volume identified by id
func (s *Stack) DeleteVolume(id string) error {
	log.Debugf("openstack.Stack.DeleteVolume(%s) called", id)
	defer log.Debugf("openstack.Stack.DeleteVolume(%s) done", id)

	if s == nil {
		panic("Calling s.DeleteVolume with s==nil!")
	}

	var (
		err     error
		timeout = 30 * time.Second
	)

	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			r := volumes.Delete(s.Volume, id)
			err := r.ExtractErr()
			if err != nil {
				switch err.(type) {
				case gc.ErrDefault400:
					return fmt.Errorf("volume not in state 'available'")
				default:
					return err
				}
			}
			return nil
		},
		timeout,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case retry.ErrTimeout:
			if err != nil {
				return fmt.Errorf("timeout after %v to delete volume: %v", timeout, err)
			}
		}
		log.Debugf("Error deleting volume: %+v", retryErr)
		return errors.Wrap(retryErr, fmt.Sprintf("Error deleting volume: %v", retryErr))
	}
	return nil
}

// CreateVolumeAttachment attaches a volume to an host
// - 'name' of the volume attachment
// - 'volume' to attach
// - 'host' on which the volume is attached
func (s *Stack) CreateVolumeAttachment(request model.VolumeAttachmentRequest) (string, error) {
	log.Debugf("openstack.Stack.CreateVolumeAttachment(%s) called", request.Name)
	defer log.Debugf("openstack.Stack.CreateVolumeAttachment(%s) done", request.Name)

	if s == nil {
		panic("Calling s.CreateVolumeAttachment with s==nil!")
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
func (s *Stack) GetVolumeAttachment(serverID, id string) (*model.VolumeAttachment, error) {
	log.Debugf("openstack.Stack.GetVolumeAttachment(%s) called", id)
	defer log.Debugf("openstack.Stack.GetVolumeAttachment(%s) done", id)

	if s == nil {
		panic("Calling s.GetVolumeAttachment with s==nil!")
	}

	va, err := volumeattach.Get(s.Compute, serverID, id).Extract()
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
func (s *Stack) ListVolumeAttachments(serverID string) ([]model.VolumeAttachment, error) {
	log.Debugf("openstack.Stack.ListVolumeAttachments(%s) called", serverID)
	defer log.Debugf("openstack.Stack.ListVolumeAttachments(%s) done", serverID)

	if s == nil {
		panic("Calling s.ListVolumeAttachments with s==nil!")
	}

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
func (s *Stack) DeleteVolumeAttachment(serverID, vaID string) error {
	log.Debugf("openstack.Stack.DeleteVolumeAttachment(%s) called", serverID)
	defer log.Debugf("openstack.Stack.DeleteVolumeAttachment(%s) done", serverID)

	if s == nil {
		panic("Calling s.DeleteVolumeAttachment with s==nil!")
	}

	r := volumeattach.Delete(client.Compute, serverID, vaID)
	err := r.ExtractErr()
	if err != nil {
		spew.Dump(r)
		log.Debugf("Error deleting volume attachment: deleting attachments: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting volume attachment '%s': %s", vaID, ProviderErrorToString(err)))
	}
	return nil
}
