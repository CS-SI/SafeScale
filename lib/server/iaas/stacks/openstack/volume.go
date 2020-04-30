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

package openstack

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"

	"github.com/gophercloud/gophercloud"
	volumesv1 "github.com/gophercloud/gophercloud/openstack/blockstorage/v1/volumes"
	volumesv2 "github.com/gophercloud/gophercloud/openstack/blockstorage/v2/volumes"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/volumeattach"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumestate"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// toVolumeState converts a Volume status returned by the OpenStack driver into VolumeState enum
func toVolumeState(status string) volumestate.Enum {
	switch status {
	case "creating":
		return volumestate.CREATING
	case "available":
		return volumestate.AVAILABLE
	case "attaching":
		return volumestate.ATTACHING
	case "detaching":
		return volumestate.DETACHING
	case "in-use":
		return volumestate.USED
	case "deleting":
		return volumestate.DELETING
	case "error", "error_deleting", "error_backing-up", "error_restoring", "error_extending":
		return volumestate.ERROR
	default:
		return volumestate.OTHER
	}
}

func (s *Stack) getVolumeType(speed volumespeed.Enum) string {
	for t, s := range s.cfgOpts.VolumeSpeeds {
		if s == speed {
			return t
		}
	}
	switch speed {
	case volumespeed.SSD:
		return s.getVolumeType(volumespeed.HDD)
	case volumespeed.HDD:
		return s.getVolumeType(volumespeed.COLD)
	default:
		return ""
	}
}

func (s *Stack) getVolumeSpeed(vType string) volumespeed.Enum {
	speed, ok := s.cfgOpts.VolumeSpeeds[vType]
	if ok {
		return speed
	}
	return volumespeed.HDD
}

// CreateVolume creates a block volume
// - name is the name of the volume
// - size is the size of the volume in GB
// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
func (s *Stack) CreateVolume(request abstract.VolumeRequest) (volume *abstract.Volume, err error) {
	if s == nil {
		return nil, fail.InvalidInstanceReport()
	}
	if request.Name == "" {
		return nil, fail.InvalidParameterReport("request.Name", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("stack.volume"), "(%s)", request.Name).WithStopwatch().Entering().OnExitTrace()

	volume, err = s.GetVolume(request.Name)
	if err != nil {
		if _, ok := err.(fail.NotFound); !ok {
			return nil, err
		}
	}
	if volume != nil {
		return nil, abstract.ResourceDuplicateError("volume", request.Name)
	}

	az, err := s.SelectedAvailabilityZone()
	if err != nil {
		return nil, abstract.ResourceDuplicateError("volume", request.Name)
	}

	var v abstract.Volume
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
			err = fail.InconsistentReport("volume creation seems to have succeeded, but returned nil value is unexpected")
			break
		}
		v = abstract.Volume{
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
			err = fail.InconsistentReport("volume creation seems to have succeeded, but returned nil value is unexpected")
			break
		}
		v = abstract.Volume{
			ID:    vol.ID,
			Name:  vol.Name,
			Size:  vol.Size,
			Speed: s.getVolumeSpeed(vol.VolumeType),
			State: toVolumeState(vol.Status),
		}
	default:
		err = fail.NotImplementedReport("unmanaged service 'volume' version '%s'", s.versions["volume"])
	}
	if err != nil {
		return nil, fail.Wrap(err, fmt.Sprintf("error creating volume : %s", ProviderErrorToString(err)))
	}

	return &v, nil
}

// GetVolume returns the volume identified by id
func (s *Stack) GetVolume(id string) (*abstract.Volume, error) {
	if s == nil {
		return nil, fail.InvalidInstanceReport()
	}
	if id == "" {
		return nil, fail.InvalidParameterReport("id", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("stack.volume"), "(%s)", id).WithStopwatch().Entering().OnExitTrace()

	r := volumesv2.Get(s.VolumeClient, id)
	volume, err := r.Extract()
	if err != nil {
		if _, ok := err.(gophercloud.ErrDefault404); ok {
			return nil, abstract.ResourceNotFoundError("volume", id)
		}
		return nil, fail.Wrap(err, fmt.Sprintf("error getting volume: %s", ProviderErrorToString(err)))
	}

	av := abstract.Volume{
		ID:    volume.ID,
		Name:  volume.Name,
		Size:  volume.Size,
		Speed: s.getVolumeSpeed(volume.VolumeType),
		State: toVolumeState(volume.Status),
	}
	return &av, nil
}

// ListVolumes returns the list of all volumes known on the current tenant
func (s *Stack) ListVolumes() ([]abstract.Volume, error) {
	if s == nil {
		return nil, fail.InvalidInstanceReport()
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("stack.volume"), "").WithStopwatch().Entering().OnExitTrace()

	var vs []abstract.Volume
	err := volumesv2.List(s.VolumeClient, volumesv2.ListOpts{}).EachPage(func(page pagination.Page) (bool, error) {
		list, err := volumesv2.ExtractVolumes(page)
		if err != nil {
			logrus.Errorf("Report listing volumes: volume extraction: %+v", err)
			return false, err
		}
		for _, vol := range list {
			av := abstract.Volume{
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
			return nil, fail.Wrap(err, fmt.Sprintf("error listing volume types: %s", ProviderErrorToString(err)))
		}
		logrus.Warnf("Complete volume list empty")
	}
	return vs, nil
}

// DeleteVolume deletes the volume identified by id
func (s *Stack) DeleteVolume(id string) (err error) {
	if s == nil {
		return fail.InvalidInstanceReport()
	}
	if id == "" {
		return fail.InvalidParameterReport("id", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("stack.volume"), "("+id+")").WithStopwatch().Entering().OnExitTrace()

	var (
		timeout = temporal.GetBigDelay()
	)

	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			r := volumesv2.Delete(s.VolumeClient, id, nil)
			err := r.ExtractErr()
			if err != nil {
				switch err.(type) {
				case gophercloud.ErrDefault400:
					return fail.NotAvailableReport("volume not in state 'available'")
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
func (s *Stack) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, error) {
	if s == nil {
		return "", fail.InvalidInstanceReport()
	}
	if request.Name == "" {
		return "", fail.InvalidParameterReport("request.Name", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("stack.volume"), "("+request.Name+")").WithStopwatch().Entering().OnExitTrace()

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
		return "", fail.Wrap(err, fmt.Sprintf("error creating volume attachment between server %s and volume %s: %s", request.HostID, request.VolumeID, ProviderErrorToString(err)))
	}

	return va.ID, nil
}

// GetVolumeAttachment returns the volume attachment identified by id
func (s *Stack) GetVolumeAttachment(serverID, id string) (*abstract.VolumeAttachment, error) {
	if s == nil {
		return nil, fail.InvalidInstanceReport()
	}
	if serverID == "" {
		return nil, fail.InvalidParameterReport("serverID", "cannot be empty string")
	}
	if id == "" {
		return nil, fail.InvalidParameterReport("id", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("stack.volume"), "('"+serverID+"', '"+id+"')").WithStopwatch().Entering().OnExitTrace()

	va, err := volumeattach.Get(s.ComputeClient, serverID, id).Extract()
	if err != nil {
		return nil, fail.Wrap(err, fmt.Sprintf("error getting volume attachment %s: %s", id, ProviderErrorToString(err)))
	}
	return &abstract.VolumeAttachment{
		ID:       va.ID,
		ServerID: va.ServerID,
		VolumeID: va.VolumeID,
		Device:   va.Device,
	}, nil
}

// ListVolumeAttachments lists available volume attachment
func (s *Stack) ListVolumeAttachments(serverID string) ([]abstract.VolumeAttachment, error) {
	if s == nil {
		return nil, fail.InvalidInstanceReport()
	}
	if serverID == "" {
		return nil, fail.InvalidParameterReport("serverID", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("stack.volume"), "('"+serverID+"')").WithStopwatch().Entering().OnExitTrace()

	var vs []abstract.VolumeAttachment
	err := volumeattach.List(s.ComputeClient, serverID).EachPage(func(page pagination.Page) (bool, error) {
		list, err := volumeattach.ExtractVolumeAttachments(page)
		if err != nil {
			return false, fail.Wrap(err, "Report listing volume attachment: extracting attachments")
		}
		for _, va := range list {
			ava := abstract.VolumeAttachment{
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
		return nil, fail.Wrap(err, fmt.Sprintf("error listing volume types: %s", ProviderErrorToString(err)))
	}
	return vs, nil
}

// DeleteVolumeAttachment deletes the volume attachment identified by id
func (s *Stack) DeleteVolumeAttachment(serverID, vaID string) error {
	if s == nil {
		return fail.InvalidInstanceReport()
	}
	if serverID == "" {
		return fail.InvalidParameterReport("serverID", "cannot be empty string")
	}
	if vaID == "" {
		return fail.InvalidParameterReport("vaID", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("stack.volume"), "('"+serverID+"', '"+vaID+"')").WithStopwatch().Entering().OnExitTrace()

	r := volumeattach.Delete(s.ComputeClient, serverID, vaID)
	err := r.ExtractErr()
	if err != nil {
		return fail.Wrap(err, fmt.Sprintf("error deleting volume attachment '%s': %s", vaID, ProviderErrorToString(err)))
	}
	return nil
}
