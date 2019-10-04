/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"

	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"

	gc "github.com/gophercloud/gophercloud"
	volumesv1 "github.com/gophercloud/gophercloud/openstack/blockstorage/v1/volumes"
	volumesv2 "github.com/gophercloud/gophercloud/openstack/blockstorage/v2/volumes"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/volumeattach"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/VolumeState"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
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
	for t, s := range s.cfgOpts.VolumeSpeeds {
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
	speed, ok := s.cfgOpts.VolumeSpeeds[vType]
	if ok {
		return speed
	}
	return VolumeSpeed.HDD
}

// CreateVolume creates a block volume
// - name is the name of the volume
// - size is the size of the volume in GB
// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
func (s *Stack) CreateVolume(request resources.VolumeRequest) (volume *resources.Volume, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if request.Name == "" {
		return nil, scerr.InvalidParameterError("request.Name", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, fmt.Sprintf("(%s)", request.Name), true).WithStopwatch().GoingIn().OnExitTrace()()

	volume, err = s.GetVolume(request.Name)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); !ok {
			return nil, err
		}
	}
	if volume != nil {
		return nil, resources.ResourceDuplicateError("volume", request.Name)
	}

	az, err := s.SelectedAvailabilityZone()
	if err != nil {
		return nil, resources.ResourceDuplicateError("volume", request.Name)
	}

	var v resources.Volume
	switch s.versions["volume"] {
	case "v1":
		var vol *volumesv1.Volume
		vol, err = volumesv1.Create(s.VolumeClient, volumesv1.CreateOpts{
			AvailabilityZone: az,
			Name:             request.Name,
			Size:             request.Size,
			VolumeType:       s.getVolumeType(request.Speed),
		}).Extract()
		if err != nil {
			break
		}
		if vol == nil {
			err = fmt.Errorf("volume creation seems to have succeeded, but returned nil value is unexpected")
			break
		}
		v = resources.Volume{
			ID:    vol.ID,
			Name:  vol.Name,
			Size:  vol.Size,
			Speed: s.getVolumeSpeed(vol.VolumeType),
			State: toVolumeState(vol.Status),
		}
	case "v2":
		var vol *volumesv2.Volume
		vol, err = volumesv2.Create(s.VolumeClient, volumesv2.CreateOpts{
			AvailabilityZone: az,
			Name:             request.Name,
			Size:             request.Size,
			VolumeType:       s.getVolumeType(request.Speed),
		}).Extract()
		if err != nil {
			break
		}
		if vol == nil {
			err = fmt.Errorf("volume creation seems to have succeeded, but returned nil value is unexpected")
			break
		}
		v = resources.Volume{
			ID:    vol.ID,
			Name:  vol.Name,
			Size:  vol.Size,
			Speed: s.getVolumeSpeed(vol.VolumeType),
			State: toVolumeState(vol.Status),
		}
	default:
		err = fmt.Errorf("unmanaged service 'volume' version '%s'", s.versions["volume"])
	}
	if err != nil {
		return nil, scerr.Wrap(err, fmt.Sprintf("error creating volume : %s", ProviderErrorToString(err)))
	}

	return &v, nil
}

// GetVolume returns the volume identified by id
func (s *Stack) GetVolume(id string) (*resources.Volume, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if id == "" {
		return nil, scerr.InvalidParameterError("id", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, fmt.Sprintf("(%s)", id), true).WithStopwatch().GoingIn().OnExitTrace()()

	r := volumesv2.Get(s.VolumeClient, id)
	volume, err := r.Extract()
	if err != nil {
		if _, ok := err.(gc.ErrDefault404); ok {
			return nil, resources.ResourceNotFoundError("volume", id)
		}
		return nil, scerr.Wrap(err, fmt.Sprintf("error getting volume: %s", ProviderErrorToString(err)))
	}

	av := resources.Volume{
		ID:    volume.ID,
		Name:  volume.Name,
		Size:  volume.Size,
		Speed: s.getVolumeSpeed(volume.VolumeType),
		State: toVolumeState(volume.Status),
	}
	return &av, nil
}

// ListVolumes returns the list of all volumes known on the current tenant
func (s *Stack) ListVolumes() ([]resources.Volume, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	defer concurrency.NewTracer(nil, "", true).WithStopwatch().GoingIn().OnExitTrace()()

	var vs []resources.Volume
	err := volumesv2.List(s.VolumeClient, volumesv2.ListOpts{}).EachPage(func(page pagination.Page) (bool, error) {
		list, err := volumesv2.ExtractVolumes(page)
		if err != nil {
			log.Errorf("Error listing volumes: volume extraction: %+v", err)
			return false, err
		}
		for _, vol := range list {
			av := resources.Volume{
				ID:    vol.ID,
				Name:  vol.Name,
				Size:  vol.Size,
				Speed: s.getVolumeSpeed(vol.VolumeType),
				State: toVolumeState(vol.Status),
			}
			vs = append(vs, av)
		}
		return true, nil
	})
	if err != nil || len(vs) == 0 {
		if err != nil {
			return nil, scerr.Wrap(err, fmt.Sprintf("error listing volume types: %s", ProviderErrorToString(err)))
		}
		log.Warnf("Complete volume list empty")
	}
	return vs, nil
}

// DeleteVolume deletes the volume identified by id
func (s *Stack) DeleteVolume(id string) (err error) {
	if s == nil {
		return scerr.InvalidInstanceError()
	}
	if id == "" {
		return scerr.InvalidParameterError("id", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, "("+id+")", true).WithStopwatch().GoingIn().OnExitTrace()()

	var (
		timeout = temporal.GetBigDelay()
	)

	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			r := volumesv2.Delete(s.VolumeClient, id, nil)
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
		if _, ok := retryErr.(retry.ErrTimeout); ok {
			return retryErr
		}
		return retryErr
	}
	return nil
}

// CreateVolumeAttachment attaches a volume to an host
// - 'name' of the volume attachment
// - 'volume' to attach
// - 'host' on which the volume is attached
func (s *Stack) CreateVolumeAttachment(request resources.VolumeAttachmentRequest) (string, error) {
	if s == nil {
		return "", scerr.InvalidInstanceError()
	}
	if request.Name == "" {
		return "", scerr.InvalidParameterError("request.Name", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, "("+request.Name+")", true).WithStopwatch().GoingIn().OnExitTrace()()

	// Creates the attachment
	r := volumeattach.Create(s.ComputeClient, request.HostID, volumeattach.CreateOpts{
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
		return "", scerr.Wrap(err, fmt.Sprintf("error creating volume attachment between server %s and volume %s: %s", request.HostID, request.VolumeID, ProviderErrorToString(err)))
	}

	return va.ID, nil
}

// GetVolumeAttachment returns the volume attachment identified by id
func (s *Stack) GetVolumeAttachment(serverID, id string) (*resources.VolumeAttachment, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if serverID == "" {
		return nil, scerr.InvalidParameterError("serverID", "cannot be empty string")
	}
	if id == "" {
		return nil, scerr.InvalidParameterError("id", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, "('"+serverID+"', '"+id+"')", true).WithStopwatch().GoingIn().OnExitTrace()()

	va, err := volumeattach.Get(s.ComputeClient, serverID, id).Extract()
	if err != nil {
		return nil, scerr.Wrap(err, fmt.Sprintf("error getting volume attachment %s: %s", id, ProviderErrorToString(err)))
	}
	return &resources.VolumeAttachment{
		ID:       va.ID,
		ServerID: va.ServerID,
		VolumeID: va.VolumeID,
		Device:   va.Device,
	}, nil
}

// ListVolumeAttachments lists available volume attachment
func (s *Stack) ListVolumeAttachments(serverID string) ([]resources.VolumeAttachment, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if serverID == "" {
		return nil, scerr.InvalidParameterError("serverID", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, "('"+serverID+"')", true).WithStopwatch().GoingIn().OnExitTrace()()

	var vs []resources.VolumeAttachment
	err := volumeattach.List(s.ComputeClient, serverID).EachPage(func(page pagination.Page) (bool, error) {
		list, err := volumeattach.ExtractVolumeAttachments(page)
		if err != nil {
			return false, scerr.Wrap(err, "Error listing volume attachment: extracting attachments")
		}
		for _, va := range list {
			ava := resources.VolumeAttachment{
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
		return nil, scerr.Wrap(err, fmt.Sprintf("error listing volume types: %s", ProviderErrorToString(err)))
	}
	return vs, nil
}

// DeleteVolumeAttachment deletes the volume attachment identified by id
func (s *Stack) DeleteVolumeAttachment(serverID, vaID string) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}
	if serverID == "" {
		return scerr.InvalidParameterError("serverID", "cannot be empty string")
	}
	if vaID == "" {
		return scerr.InvalidParameterError("vaID", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, "('"+serverID+"', '"+vaID+"')", true).WithStopwatch().GoingIn().OnExitTrace()()

	r := volumeattach.Delete(s.ComputeClient, serverID, vaID)
	err := r.ExtractErr()
	if err != nil {
		return scerr.Wrap(err, fmt.Sprintf("error deleting volume attachment '%s': %s", vaID, ProviderErrorToString(err)))
	}
	return nil
}
