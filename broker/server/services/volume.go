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

package services

import (
	"fmt"
	"strings"
	"time"

	"github.com/deckarep/golang-set"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/system/nfs"
	"github.com/CS-SI/SafeScale/utils/retry"
)

//go:generate mockgen -destination=../mocks/mock_volumeapi.go -package=mocks github.com/CS-SI/SafeScale/broker/server/services VolumeAPI

//VolumeAPI defines API to manipulate hosts
type VolumeAPI interface {
	Delete(ref string) error
	Get(ref string) (*model.Volume, error)
	Inspect(ref string) (*model.Volume, *model.VolumeAttachment, error)
	List(all bool) ([]model.Volume, error)
	Create(name string, size int, speed VolumeSpeed.Enum) (*model.Volume, error)
	Attach(volume string, host string, path string, format string) error
	Detach(volume string, host string) error
}

//VolumeService volume service
type VolumeService struct {
	provider *providers.Service
	sshSvc   SSHAPI
}

// NewVolumeService creates a Volume service
func NewVolumeService(api *providers.Service) VolumeAPI {
	return &VolumeService{
		provider: providers.FromClient(api),
		sshSvc:   newSSHService(api, nil),
	}
}

//List returns the network list
func (svc *VolumeService) List(all bool) ([]model.Volume, error) {
	return svc.provider.ListVolumes(all)
}

//Delete deletes volume referenced by ref
func (svc *VolumeService) Delete(ref string) error {
	vol, err := svc.Get(ref)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return tbr
	}
	if vol == nil {
		return fmt.Errorf("Volume '%s' does not exist", ref)
	}

	return svc.provider.DeleteVolume(vol.ID)
}

//Get returns the volume identified by ref, ref can be the name or the id
func (svc *VolumeService) Get(ref string) (*model.Volume, error) {
	m, err := metadata.LoadVolume(svc.provider, ref)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	if m == nil {
		return nil, nil
	}
	return m.Get(), nil
}

//Inspect returns the volume identified by ref and its attachment (if any)
func (svc *VolumeService) Inspect(ref string) (*model.Volume, *model.VolumeAttachment, error) {
	mtdvol, err := metadata.LoadVolume(svc.provider, ref)
	if err != nil {
		return nil, nil, err
	}
	if mtdvol == nil {
		return nil, nil, nil
	}

	va, err := mtdvol.GetAttachment()
	if err != nil {
		return nil, nil, err
	}

	return mtdvol.Get(), va, nil
}

// Create a volume
func (svc *VolumeService) Create(name string, size int, speed VolumeSpeed.Enum) (*model.Volume, error) {
	return svc.provider.CreateVolume(model.VolumeRequest{
		Name:  name,
		Size:  size,
		Speed: speed,
	})
}

// Attach a volume to an host
func (svc *VolumeService) Attach(volumename, hostName, path, format string) error {
	// Get volume ID
	volume, err := svc.Get(volumename)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return tbr
	}
	if volume == nil {
		return errors.Wrap(model.ResourceNotFoundError("volume", volumename), "Cannot attach volume")
	}

	// Get Host ID
	hostService := NewHostService(svc.provider)
	host, err := hostService.Get(hostName)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return tbr
	}
	if host == nil {
		return errors.Wrap(model.ResourceNotFoundError("host", hostName), "Cannot attach volume")
	}

	// Note: most providers are not able to tell the real device name the volume
	//       will have on the host, so we have to use a way that can work everywhere
	// Get list of disks before attachment
	oldDiskSet, err := svc.listAttachedDevices(host)
	if err != nil {
		return fmt.Errorf("failed to get list of connected disks: %s", err)
	}

	volatt, err := svc.provider.CreateVolumeAttachment(model.VolumeAttachmentRequest{
		Name:     fmt.Sprintf("%s-%s", volume.Name, host.Name),
		ServerID: host.ID,
		VolumeID: volume.ID,
	})
	if err != nil {
		return fmt.Errorf("failed to create host-volume attachment: %v", err)
	}

	// Waits to acknowledge the volume is really attached to host
	var newDisk mapset.Set
	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			// Get new of disk after attachment
			newDiskSet, err := svc.listAttachedDevices(host)
			if err != nil {
				return fmt.Errorf("failed to get list of connected disks: %s", err)
			}
			// Isolate the new device
			newDisk = newDiskSet.Difference(oldDiskSet)
			if newDisk.Cardinality() == 0 {
				return fmt.Errorf("disk not yet attached, retrying")
			}
			return nil
		},
		2*time.Minute,
	)
	if retryErr != nil {
		return fmt.Errorf("failed to acknowledge the disk attachment after %s", 2*time.Minute)
	}

	// Updates volume attachment metadata
	deviceName := newDisk.ToSlice()[0].(string)
	volatt.Device = "/dev/" + deviceName
	err = metadata.SaveVolumeAttachment(svc.provider, volatt)
	if err != nil {
		derr := svc.Detach(volumename, hostName)
		if derr != nil {
			log.Warnf("Failure trying to detach volume: %v", derr)
		}
		return fmt.Errorf("failed to update volume attachment: %s", err.Error())
	}

	// Create mount point
	mountPoint := path
	if path == model.DefaultVolumeMountPoint {
		mountPoint = model.DefaultVolumeMountPoint + volume.Name
	}

	sshConfig, err := svc.sshSvc.GetConfig(host.ID)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return tbr
	}

	server, err := nfs.NewServer(sshConfig)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return tbr
	}
	err = server.MountBlockDevice(volatt.Device, mountPoint, format)

	if err != nil {
		derr := svc.Detach(volumename, hostName)
		if derr != nil {
			log.Warnf("Error trying to detach volume: %v", derr)
		}
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return tbr
	}

	// Update volume attachement info with mountpoint
	volatt.MountPoint = mountPoint
	volatt.Format = format
	mtdVol, err := metadata.LoadVolume(svc.provider, volumename)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return tbr
	}
	err = mtdVol.Attach(volatt)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return tbr
	}

	return nil
}

func (svc *VolumeService) listAttachedDevices(host *model.Host) (mapset.Set, error) {
	var (
		retcode        int
		stdout, stderr string
		err            error
	)
	cmd := "sudo lsblk -l -o NAME,TYPE | grep disk | cut -d' ' -f1"
	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			retcode, stdout, stderr, err = svc.sshSvc.Run(host.ID, cmd)
			if err != nil {
				tbr := errors.Wrap(err, "")
				log.Errorf("%+v", tbr)
				return tbr
			}
			if retcode != 0 {
				if retcode == 255 {
					return fmt.Errorf("failed to reach SSH service of host '%s', retrying", host.Name)
				}
				return fmt.Errorf(stderr)
			}
			return nil
		},
		2*time.Minute,
	)
	if retryErr != nil {
		return nil, fmt.Errorf("failed to get list of connected disks after %s: %s", 2*time.Minute, retryErr.Error())
	}
	disks := strings.Split(stdout, "\n")
	set := mapset.NewThreadUnsafeSet()
	for _, k := range disks {
		set.Add(k)
	}
	return set, nil
}

// Detach detach the volume identified by ref, ref can be the name or the id
func (svc *VolumeService) Detach(volumename string, hostName string) error {
	vol, err := svc.Get(volumename)
	if err != nil {
		return errors.Wrap(model.ResourceNotFoundError("volume", volumename), "Cannot detach volume")
	}

	// Get Host ID
	hostService := NewHostService(svc.provider)
	host, err := hostService.Get(hostName)
	if err != nil {
		return errors.Wrap(model.ResourceNotFoundError("host", hostName), "Cannot detach volume")
	}

	// providerVA, err := svc.provider.GetVolumeAttachment(host.ID, vol.ID)
	// if err != nil {
	// 	return fmt.Errorf("error getting volume attachment: %s", err)
	// }
	mdVA, err := metadata.LoadVolumeAttachment(svc.provider, host.ID, vol.ID)
	if err != nil {
		return fmt.Errorf("error getting volume attachment: %s", err)
	}
	volatt := mdVA.Get()

	sshConfig, err := svc.sshSvc.GetConfig(host.ID)
	if err != nil {
		tbr := errors.Wrap(err, "error getting ssh config")
		log.Errorf("%+v", tbr)
		return tbr
	}

	server, err := nfs.NewServer(sshConfig)
	if err != nil {
		tbr := errors.Wrap(err, "error creating nfs service")
		log.Errorf("%+v", tbr)
		return tbr
	}
	err = server.UnmountBlockDevice(volatt.Device)
	if err != nil {
		tbr := errors.Wrap(err, "error unmounting block device")
		log.Errorf("%+v", tbr)
		return tbr
	}

	// Finaly delete the attachment
	return svc.provider.DeleteVolumeAttachment(host.ID, vol.ID)
}
