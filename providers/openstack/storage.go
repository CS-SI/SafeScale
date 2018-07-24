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
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/api/VolumeSpeed"
	"github.com/CS-SI/SafeScale/providers/api/VolumeState"
	metadata "github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/gophercloud/gophercloud/openstack/objectstorage/v1/objects"

	"github.com/gophercloud/gophercloud/openstack/objectstorage/v1/containers"

	"github.com/gophercloud/gophercloud/openstack/blockstorage/v1/volumes"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/volumeattach"
	"github.com/gophercloud/gophercloud/pagination"
)

//toVM converts a Volume status returned by the OpenStack driver into VolumeState enum
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

//CreateVolume creates a block volume
//- name is the name of the volume
//- size is the size of the volume in GB
//- volumeType is the type of volume to create, if volumeType is empty the driver use a default type
func (client *Client) CreateVolume(request api.VolumeRequest) (*api.Volume, error) {
	vol, err := volumes.Create(client.Volume, volumes.CreateOpts{
		Name:       request.Name,
		Size:       request.Size,
		VolumeType: client.getVolumeType(request.Speed),
	}).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error creating volume : %s", errorString(err))
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
		client.DeleteVolume(v.ID)
		return nil, fmt.Errorf("Error creating volume : %s", errorString(err))
	}

	return &v, nil
}

//GetVolume returns the volume identified by id
func (client *Client) GetVolume(id string) (*api.Volume, error) {
	vol, err := volumes.Get(client.Volume, id).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error getting volume: %s", errorString(err))
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

func (client *Client) ListVolumes(all bool) ([]api.Volume, error) {
	if all {
		return client.listAllVolumes()
	}
	return client.listMonitoredVolumes()

}

//ListVolumes list available volumes
func (client *Client) listAllVolumes() ([]api.Volume, error) {
	var vs []api.Volume
	err := volumes.List(client.Volume, volumes.ListOpts{}).EachPage(func(page pagination.Page) (bool, error) {
		list, err := volumes.ExtractVolumes(page)
		if err != nil {
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
			vs = append(vs, av)
		}
		return true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("Error listing volume types: %s", errorString(err))
	}
	return vs, nil
}

//listMonitoredVolumess lists available Volumes created by SafeScale (ie registered in object storage)
func (client *Client) listMonitoredVolumes() ([]api.Volume, error) {
	var vols []api.Volume
	m, err := metadata.NewVolume(providers.FromClient(client))
	if err != nil {
		return vols, err
	}
	err = m.Browse(func(vol *api.Volume) error {
		vols = append(vols, *vol)
		return nil
	})
	if err != nil {
		return vols, err
	}
	return vols, nil
}

//DeleteVolume deletes the volume identified by id
func (client *Client) DeleteVolume(id string) error {
	err := volumes.Delete(client.Volume, id).ExtractErr()
	if err != nil {
		return fmt.Errorf("Error deleting volume: %s", errorString(err))
	}
	err = metadata.RemoveVolume(providers.FromClient(client), id)
	if err != nil {
		return fmt.Errorf("Error deleting volume: %s", errorString(err))
	}
	return nil
}

//CreateVolumeAttachment attaches a volume to a VM
//- name the name of the volume attachment
//- volume the volume to attach
//- vm the VM on which the volume is attached
func (client *Client) CreateVolumeAttachment(request api.VolumeAttachmentRequest) (*api.VolumeAttachment, error) {
	va, err := volumeattach.Create(client.Compute, request.ServerID, volumeattach.CreateOpts{
		VolumeID: request.VolumeID,
	}).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error creating volume attachment between server %s and volume %s: %s", request.ServerID, request.VolumeID, errorString(err))
	}

	vaapi := &api.VolumeAttachment{
		ID:       va.ID,
		ServerID: va.ServerID,
		VolumeID: va.VolumeID,
		Device:   va.Device,
	}

	mtdVol, err := metadata.LoadVolume(providers.FromClient(client), request.VolumeID)
	if err != nil {
		// TODO ? Detach volume ?
		return nil, err
	}
	err = mtdVol.Attach(vaapi)
	if err != nil {
		// TODO ? Detach volume ?
		return vaapi, err
	}

	return vaapi, nil
}

//GetVolumeAttachment returns the volume attachment identified by id
func (client *Client) GetVolumeAttachment(serverID, id string) (*api.VolumeAttachment, error) {
	va, err := volumeattach.Get(client.Compute, serverID, id).Extract()
	if err != nil {
		return nil, fmt.Errorf("Error getting volume attachment %s: %s", id, errorString(err))
	}
	return &api.VolumeAttachment{
		ID:       va.ID,
		ServerID: va.ServerID,
		VolumeID: va.VolumeID,
		Device:   va.Device,
	}, nil
}

//ListVolumeAttachments lists available volume attachment
func (client *Client) ListVolumeAttachments(serverID string) ([]api.VolumeAttachment, error) {
	var vs []api.VolumeAttachment
	err := volumeattach.List(client.Compute, serverID).EachPage(func(page pagination.Page) (bool, error) {
		list, err := volumeattach.ExtractVolumeAttachments(page)
		if err != nil {
			return false, err
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
		return nil, fmt.Errorf("Error listing volume types: %s", errorString(err))
	}
	return vs, nil
}

//DeleteVolumeAttachment deletes the volume attachment identifed by id
func (client *Client) DeleteVolumeAttachment(serverID, id string) error {
	va, err := client.GetVolumeAttachment(serverID, id)
	if err != nil {
		return fmt.Errorf("Error deleting volume attachment %s: %s", id, errorString(err))
	}

	err = volumeattach.Delete(client.Compute, serverID, id).ExtractErr()
	if err != nil {
		return fmt.Errorf("Error deleting volume attachment %s: %s", id, errorString(err))
	}

	mtdVol, err := metadata.LoadVolume(providers.FromClient(client), id)
	if err != nil {
		return fmt.Errorf("Error deleting volume attachment %s: %s", id, errorString(err))
	}

	err = mtdVol.Detach(va)
	if err != nil {
		return fmt.Errorf("Error deleting volume attachment %s: %s", id, errorString(err))
	}

	return nil
}

//CreateContainer creates an object container
func (client *Client) CreateContainer(name string) error {
	opts := containers.CreateOpts{
		//		Metadata: meta,
	}
	_, err := containers.Create(client.Container, name, opts).Extract()
	if err != nil {
		return fmt.Errorf("Error creating container %s: %s", name, errorString(err))
	}

	return nil
}

//DeleteContainer deletes an object container
func (client *Client) DeleteContainer(name string) error {
	_, err := containers.Delete(client.Container, name).Extract()
	if err != nil {
		return fmt.Errorf("Error deleting container %s: %s", name, errorString(err))
	}
	return err
}

//UpdateContainer updates an object container
func (client *Client) UpdateContainer(name string, meta map[string]string) error {
	_, err := containers.Update(client.Container, name, containers.UpdateOpts{
		Metadata: meta,
	}).Extract()
	if err != nil {
		return fmt.Errorf("Error updating container %s: %s", name, errorString(err))
	}
	return nil
}

//GetContainerMetadata get an object container metadata
func (client *Client) GetContainerMetadata(name string) (map[string]string, error) {
	meta, err := containers.Get(client.Container, name).ExtractMetadata()
	if err != nil {
		return nil, fmt.Errorf("Error getting container %s: %s", name, errorString(err))
	}
	return meta, nil

}

//GetContainer get container info
func (client *Client) GetContainer(name string) (*api.ContainerInfo, error) {
	meta, err := containers.Get(client.Container, name).ExtractMetadata()
	_ = meta

	if err != nil {
		return nil, fmt.Errorf("Error getting container %s: %s", name, errorString(err))
	}
	return &api.ContainerInfo{
		Name:       name,
		VM:         "TODO VM",
		MountPoint: "TODO mountpoint",
		NbItems:    -1,
	}, nil

}

//ListContainers list object containers
func (client *Client) ListContainers() ([]string, error) {
	opts := &containers.ListOpts{Full: true}

	pager := containers.List(client.Container, opts)

	var containerList []string
	err := pager.EachPage(func(page pagination.Page) (bool, error) {

		// Get a slice of strings, i.e. container names
		containerNames, err := containers.ExtractNames(page)
		if err != nil {
			return false, err
		}
		for _, n := range containerNames {
			containerList = append(containerList, n)
		}

		return true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("Error listing containers: %s", errorString(err))
	}
	return containerList, nil
}

//PutObject put an object into an object container
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
		return fmt.Errorf("Error creating object %s in container %s : %s", obj.Name, container, errorString(err))
	}
	return nil
}

//UpdateObjectMetadata update an object into an object container
func (client *Client) UpdateObjectMetadata(container string, obj api.Object) error {
	var ti time.Time
	opts := objects.UpdateOpts{
		Metadata: obj.Metadata,
	}
	if ti != obj.DeleteAt {
		opts.DeleteAt = int(obj.DeleteAt.Unix())
	}
	_, err := objects.Update(client.Container, container, obj.Name, opts).Extract()
	return err
}

//GetObject get  object content from an object container
func (client *Client) GetObject(container string, name string, ranges []api.Range) (*api.Object, error) {
	var rList []string
	for _, r := range ranges {
		rList = append(rList, r.String())
	}
	sRanges := strings.Join(rList, ",")
	res := objects.Download(client.Container, container, name, objects.DownloadOpts{
		Range: fmt.Sprintf("bytes=%s", sRanges),
	})
	content, err := res.ExtractContent()
	if err != nil {
		return nil, fmt.Errorf("Error getting object %s from %s : %s", name, container, errorString(err))
	}
	metadata := make(map[string]string)
	for k, v := range res.Header {
		if strings.HasPrefix(k, "X-Object-Meta-") {
			key := strings.TrimPrefix(k, "X-Object-Meta-")
			metadata[key] = v[0]
		}
	}
	header, err := res.Extract()
	if err != nil {
		return nil, fmt.Errorf("Error getting object %s from %s : %s", name, container, errorString(err))
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
		Metadata:      metadata,
		Date:          header.Date,
		LastModified:  header.LastModified,
		ContentType:   header.ContentType,
		ContentLength: header.ContentLength,
	}, nil
}

//GetObjectMetadata get  object metadata from an object container
func (client *Client) GetObjectMetadata(container string, name string) (*api.Object, error) {

	res := objects.Get(client.Container, container, name, objects.GetOpts{})
	meta, err := res.ExtractMetadata()

	if err != nil {
		return nil, fmt.Errorf("Error getting object content: %s", errorString(err))
	}
	header, err := res.Extract()
	if err != nil {
		return nil, fmt.Errorf("Error getting object content: %s", errorString(err))
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

//ListObjects list objects of a container
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
			return false, err
		}
		objectList = append(objectList, objectNames...)
		return true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("Error listing objects of container '%s': %s", container, errorString(err))
	}
	return objectList, nil
}

//CopyObject copies an object
func (client *Client) CopyObject(containerSrc, objectSrc, objectDst string) error {

	opts := &objects.CopyOpts{
		Destination: objectDst,
	}

	result := objects.Copy(client.Container, containerSrc, objectSrc, opts)

	_, err := result.Extract()
	if err != nil {
		return fmt.Errorf("Error copying object %s into %s from container %s : %s", objectSrc, objectDst, containerSrc, errorString(err))
	}
	return nil
}

//DeleteObject deleta an object from a container
func (client *Client) DeleteObject(container, object string) error {
	_, err := objects.Delete(client.Container, container, object, objects.DeleteOpts{}).Extract()
	if err != nil {
		return fmt.Errorf("Error deleting objects %s of container %s: %s", object, container, errorString(err))
	}
	return nil

}
