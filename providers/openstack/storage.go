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
	"bytes"
	"fmt"
	"github.com/pkg/errors"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/providers/enums/VolumeState"
	"github.com/CS-SI/SafeScale/providers/metadata"

	"github.com/gophercloud/gophercloud/openstack/blockstorage/v1/volumes"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/volumeattach"
	"github.com/gophercloud/gophercloud/openstack/objectstorage/v1/containers"
	"github.com/gophercloud/gophercloud/openstack/objectstorage/v1/objects"
	"github.com/gophercloud/gophercloud/pagination"
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
func (client *Client) CreateVolume(request api.VolumeRequest) (*api.Volume, error) {
	// Check if a volume already exists with the same name
	volume, err := metadata.LoadVolume(providers.FromClient(client), request.Name)
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
	v := api.Volume{
		ID:    vol.ID,
		Name:  vol.Name,
		Size:  vol.Size,
		Speed: client.getVolumeSpeed(vol.VolumeType),
		State: toVolumeState(vol.Status),
	}
	err = metadata.SaveVolume(providers.FromClient(client), &v)
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
func (client *Client) GetVolume(id string) (*api.Volume, error) {
	vol, err := volumes.Get(client.Volume, id).Extract()
	if err != nil {
		log.Debugf("Error getting volume: getting volume invocation: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting volume: %s", ProviderErrorToString(err)))
	}
	av := api.Volume{
		ID:    vol.ID,
		Name:  vol.Name,
		Size:  vol.Size,
		Speed: client.getVolumeSpeed(vol.VolumeType),
		State: toVolumeState(vol.Status),
	}
	return &av, nil
}

//ListVolumes return the list of all volume known on the current tenant (all=ture)
//or 'only' thode monitored by safescale (all=false) ie those monitored by metadata
func (client *Client) ListVolumes(all bool) ([]api.Volume, error) {
	if all {
		return client.listAllVolumes()
	}
	return client.listMonitoredVolumes()

}

// ListVolumes list available volumes
func (client *Client) listAllVolumes() ([]api.Volume, error) {
	var vs []api.Volume
	err := volumes.List(client.Volume, volumes.ListOpts{}).EachPage(func(page pagination.Page) (bool, error) {
		list, err := volumes.ExtractVolumes(page)
		if err != nil {
			log.Errorf("Error listing volumes: volume extraction: %+v", err)
			return false, err
		}
		for _, vol := range list {
			av := api.Volume{
				ID:    vol.ID,
				Name:  vol.Name,
				Size:  vol.Size,
				Speed: client.getVolumeSpeed(vol.VolumeType),
				State: toVolumeState(vol.Status),
			}
			log.Debugf("Building volume list")
			vs = append(vs, av)
		}
		return true, nil
	})
	if err != nil || len(vs) == 0{
		if err != nil {
			log.Debugf("Error listing volumes: list invocation: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf("Error listing volume types: %s", ProviderErrorToString(err)))
		} else {
			// log.Debugf("Complete volume list empty")
		}
	}
	return vs, nil
}

// listMonitoredVolumess lists available Volumes created by SafeScale (ie registered in object storage)
func (client *Client) listMonitoredVolumes() ([]api.Volume, error) {
	var vols []api.Volume
	m := metadata.NewVolume(providers.FromClient(client))
	err := m.Browse(func(vol *api.Volume) error {
		vols = append(vols, *vol)
		return nil
	})
	if len(vols) == 0 || err != nil {
		if err != nil {
			log.Debugf("Error listing monitored volumes: browsing volumes: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf("Error listing volumes : %s", ProviderErrorToString(err)))
		} else {
			// log.Debugf("Volume list empty !")
		}
	}
	return vols, nil
}

// DeleteVolume deletes the volume identified by id
func (client *Client) DeleteVolume(id string) error {
	volume, err := metadata.LoadVolume(providers.FromClient(client), id)
	if err != nil {
		log.Debugf("Error deleting volume: loading metadata: %+v", err)
		return errors.Wrap(err, "Error deleting volume: loading metadata")
	}
	if volume == nil {
		log.Debugf("Error deleting volume: volume not found: %+v", err)
		return errors.Wrap(err, providers.ResourceNotFoundError("volume", id).Error())
	}

	err = volumes.Delete(client.Volume, id).ExtractErr()
	if err != nil {
		log.Debugf("Error deleting volume: actual delete call: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting volume: %s", ProviderErrorToString(err)))
	}
	err = metadata.RemoveVolume(providers.FromClient(client), id)
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
func (client *Client) CreateVolumeAttachment(request api.VolumeAttachmentRequest) (*api.VolumeAttachment, error) {
	// Create the attachment
	va, err := volumeattach.Create(client.Compute, request.ServerID, volumeattach.CreateOpts{
		VolumeID: request.VolumeID,
	}).Extract()
	if err != nil {
		log.Debugf("Error creating volume attachment: actual attachment creation: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error creating volume attachment between server %s and volume %s: %s", request.ServerID, request.VolumeID, ProviderErrorToString(err)))
	}

	vaapi := &api.VolumeAttachment{
		ID:       va.ID,
		ServerID: va.ServerID,
		VolumeID: va.VolumeID,
		Device:   va.Device,
	}

	// Update the metadata

	mtdVol, err := metadata.LoadVolume(providers.FromClient(client), request.VolumeID)
	if err != nil {

		// Detach volume
		detach_err := volumeattach.Delete(client.Compute, va.ServerID, va.ID).ExtractErr()
		if detach_err != nil {
			log.Debugf("Error creating volume attachment: attachment deletion: %+v", detach_err)
			return nil, errors.Wrap(detach_err, fmt.Sprintf("Error deleting volume attachment %s: %s", va.ID, ProviderErrorToString(detach_err)))
		}

		log.Debugf("Error creating volume attachment: loading metadata: %+v", err)
		return nil, errors.Wrap(err, "Error creating volume attachment: loading metadata")
	}
	err = mtdVol.Attach(vaapi)
	if err != nil {
		// Detach volume
		detach_err := volumeattach.Delete(client.Compute, va.ServerID, va.ID).ExtractErr()
		if detach_err != nil {
			log.Debugf("Error creating volume attachemnt: attachment deletion: %+v", detach_err)
			return nil, errors.Wrap(detach_err, fmt.Sprintf("Error deleting volume attachment %s: %s", va.ID, ProviderErrorToString(detach_err)))
		}

		log.Debugf("Error creating volume attachment: volume attachment call: %+v", err)
		return vaapi, errors.Wrap(err, "Error creating volume attachment: volume attachment call")
	}

	return vaapi, nil
}

// GetVolumeAttachment returns the volume attachment identified by id
func (client *Client) GetVolumeAttachment(serverID, id string) (*api.VolumeAttachment, error) {
	va, err := volumeattach.Get(client.Compute, serverID, id).Extract()
	if err != nil {
		log.Debugf("Error getting volume attachment: get call: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting volume attachment %s: %s", id, ProviderErrorToString(err)))
	}
	return &api.VolumeAttachment{
		ID:       va.ID,
		ServerID: va.ServerID,
		VolumeID: va.VolumeID,
		Device:   va.Device,
	}, nil
}

// ListVolumeAttachments lists available volume attachment
func (client *Client) ListVolumeAttachments(serverID string) ([]api.VolumeAttachment, error) {
	var vs []api.VolumeAttachment
	err := volumeattach.List(client.Compute, serverID).EachPage(func(page pagination.Page) (bool, error) {
		list, err := volumeattach.ExtractVolumeAttachments(page)
		if err != nil {
			log.Debugf("Error listing volume attachment: extracting attachments: %+v", err)
			return false, errors.Wrap(err, "Error listing volume attachment: extracting attachments")
		}
		for _, va := range list {
			ava := api.VolumeAttachment{
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

	mtdVol, err := metadata.LoadVolume(providers.FromClient(client), id)
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

// CreateContainer creates an object container
func (client *Client) CreateContainer(name string) error {
	opts := containers.CreateOpts{
		//		Metadata: meta,
	}
	_, err := containers.Create(client.Container, name, opts).Extract()
	if err != nil {
		log.Debugf("Error creating container: container creation call: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error creating container %s: %s", name, ProviderErrorToString(err)))
	}

	return nil
}

// DeleteContainer deletes an object container
func (client *Client) DeleteContainer(name string) error {
	_, err := containers.Delete(client.Container, name).Extract()
	if err != nil {
		log.Debugf("Error deleting container: container deletion call: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting container %s: %s", name, ProviderErrorToString(err)))
	}
	return err
}

// UpdateContainer updates an object container
func (client *Client) UpdateContainer(name string, meta map[string]string) error {
	_, err := containers.Update(client.Container, name, containers.UpdateOpts{
		Metadata: meta,
	}).Extract()
	if err != nil {
		log.Debugf("Error updating container: container update call: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error updating container %s: %s", name, ProviderErrorToString(err)))
	}
	return nil
}

// GetContainerMetadata get an object container metadata
func (client *Client) GetContainerMetadata(name string) (map[string]string, error) {
	meta, err := containers.Get(client.Container, name, containers.GetOpts{}).ExtractMetadata()
	if err != nil {
		log.Debugf("Error getting container metadata: getting container call: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting container %s: %s", name, ProviderErrorToString(err)))
	}
	return meta, nil

}

// GetContainer get container info
func (client *Client) GetContainer(name string) (*api.ContainerInfo, error) {
	meta, err := containers.Get(client.Container, name, containers.GetOpts{}).ExtractMetadata()
	_ = meta

	if err != nil {
		log.Debugf("Error getting container: getting container call: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting container %s: %s", name, ProviderErrorToString(err)))
	}
	return &api.ContainerInfo{
		Name:       name,
		Host:       "TODO Host",
		MountPoint: "TODO mountpoint",
		NbItems:    -1,
	}, nil

}

// ListContainers list object containers
func (client *Client) ListContainers() ([]string, error) {
	opts := &containers.ListOpts{Full: true}

	pager := containers.List(client.Container, opts)

	var containerList []string
	err := pager.EachPage(func(page pagination.Page) (bool, error) {

		// Get a slice of strings, i.e. container names
		containerNames, err := containers.ExtractNames(page)
		if err != nil {
			log.Errorf("Error listing containers: extracting container names: %+v", err)
			return false, err
		}
		for _, n := range containerNames {
			containerList = append(containerList, n)
		}

		return true, nil
	})
	if err != nil {
		log.Debugf("Error listing containers: pagination error: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error listing containers: %s", ProviderErrorToString(err)))
	}
	return containerList, nil
}

// PutObject put an object into an object container
func (client *Client) PutObject(container string, obj api.Object) error {
	var ti time.Time
	opts := objects.CreateOpts{
		Metadata:    obj.Metadata,
		ContentType: obj.ContentType,
		Content:     obj.Content,
	}
	if ti != obj.DeleteAt {
		opts.DeleteAt = int(obj.DeleteAt.Unix())
	}
	_, err := objects.Create(client.Container, container, obj.Name, opts).Extract()
	if err != nil {
		log.Debugf("Error putting object: object creation error: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error creating object %s in container %s : %s", obj.Name, container, ProviderErrorToString(err)))
	}
	return nil
}

// UpdateObjectMetadata update an object into an object container
func (client *Client) UpdateObjectMetadata(container string, obj api.Object) error {
	var ti time.Time
	opts := objects.UpdateOpts{
		Metadata: obj.Metadata,
	}
	if ti != obj.DeleteAt {
		opts.DeleteAt = int(obj.DeleteAt.Unix())
	}
	_, err := objects.Update(client.Container, container, obj.Name, opts).Extract()
	if err != nil {
		log.Debugf("Error updating object metadata: object update call: %+v", err)
		return errors.Wrap(err, "Error updating object metadata: object update call")
	}
	return nil
}

// GetObject get  object content from an object container
func (client *Client) GetObject(container string, name string, ranges []api.Range) (*api.Object, error) {
	var rList []string
	for _, r := range ranges {
		rList = append(rList, r.String())
	}

	sRanges := strings.Join(rList, ",")

	var res objects.DownloadResult
	if len(sRanges) == 0 {
		res = objects.Download(client.Container, container, name, objects.DownloadOpts{})
	} else {
		res = objects.Download(client.Container, container, name, objects.DownloadOpts{
			Range: fmt.Sprintf("bytes=%s", sRanges),
		})
	}

	content, err := res.ExtractContent()
	if err != nil {
		log.Debugf("Error getting object: content extraction call, downloaded range [%s]: %+v", sRanges, err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting object %s from %s : %s", name, container, ProviderErrorToString(err)))
	}
	recoveredMetadata := make(map[string]string)
	for k, v := range res.Header {
		if strings.HasPrefix(k, "X-Object-Meta-") {
			key := strings.TrimPrefix(k, "X-Object-Meta-")
			recoveredMetadata[key] = v[0]
		}
	}
	header, err := res.Extract()
	if err != nil {
		log.Debugf("Error getting object: extraction call: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting object %s from %s : %s", name, container, ProviderErrorToString(err)))
	}

	if len(ranges) > 1 {
		var buff bytes.Buffer
		sc := string(content)
		tokens := strings.Split(sc, "\r\n")
		read := false
		for _, t := range tokens {
			if len(t) == 0 {
				continue
			}
			if strings.HasPrefix(t, "Content-Range:") {
				read = true
			} else if read {
				buff.Write([]byte(t))
				read = false
			}
		}
		content = buff.Bytes()
	}

	return &api.Object{
		Content:       bytes.NewReader(content),
		DeleteAt:      header.DeleteAt,
		Metadata:      recoveredMetadata,
		Date:          header.Date,
		LastModified:  header.LastModified,
		ContentType:   header.ContentType,
		ContentLength: header.ContentLength,
	}, nil
}

// GetObjectMetadata get  object metadata from an object container
func (client *Client) GetObjectMetadata(container string, name string) (*api.Object, error) {

	res := objects.Get(client.Container, container, name, objects.GetOpts{})
	meta, err := res.ExtractMetadata()

	if err != nil {
		log.Debugf("Error getting object metadata: metadata extraction call: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting object content: %s", ProviderErrorToString(err)))
	}
	header, err := res.Extract()
	if err != nil {
		log.Debugf("Error getting object metadata: extraction call: %+v", err)
		return nil, errors.Wrap(err, fmt.Sprintf("Error getting object content: %s", ProviderErrorToString(err)))
	}

	return &api.Object{
		DeleteAt:      header.DeleteAt,
		Metadata:      meta,
		Date:          header.Date,
		LastModified:  header.LastModified,
		ContentType:   header.ContentType,
		ContentLength: header.ContentLength,
	}, nil
}

// ListObjects list objects of a container
func (client *Client) ListObjects(container string, filter api.ObjectFilter) ([]string, error) {
	// We have the option of filtering objects by their attributes
	opts := &objects.ListOpts{
		Full:   false,
		Path:   filter.Path,
		Prefix: filter.Prefix,
	}

	pager := objects.List(client.Container, container, opts)
	var objectList []string
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		objectNames, err := objects.ExtractNames(page)
		if err != nil {
			log.Errorf("Error listing objects: name extraction call: %+v", err)
			return false, err
		}
		objectList = append(objectList, objectNames...)
		return true, nil
	})
	if (err != nil) || (len(objectList) == 0) {
		if err != nil {
			log.Debugf("Error listing objects: pagination error: %+v", err)
			return nil, errors.Wrap(err, fmt.Sprintf("Error listing objects of container '%s': %s", container, ProviderErrorToString(err)))
		}
		// log.Debugf("Listing Storage Objects: Object list empty !")
	}
	return objectList, nil
}

// CopyObject copies an object
func (client *Client) CopyObject(containerSrc, objectSrc, objectDst string) error {

	opts := &objects.CopyOpts{
		Destination: objectDst,
	}

	result := objects.Copy(client.Container, containerSrc, objectSrc, opts)

	_, err := result.Extract()
	if err != nil {
		log.Debugf("Error copying object: extraction call: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error copying object %s into %s from container %s : %s", objectSrc, objectDst, containerSrc, ProviderErrorToString(err)))
	}
	return nil
}

// DeleteObject deleta an object from a container
func (client *Client) DeleteObject(container, object string) error {
	_, err := objects.Delete(client.Container, container, object, objects.DeleteOpts{}).Extract()
	if err != nil {
		log.Debugf("Error deleting object: delete call: %+v", err)
		return errors.Wrap(err, fmt.Sprintf("Error deleting object '%s' of container %s: %s", object, container, ProviderErrorToString(err)))
	}
	return nil
}
