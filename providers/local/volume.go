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

package local

import (
	"encoding/xml"
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"
	"strings"

	"github.com/CS-SI/SafeScale/providers/model"
	libvirt "github.com/libvirt/libvirt-go"
	libvirtxml "github.com/libvirt/libvirt-go-xml"
)

//-------------Utils----------------------------------------------------------------------------------------------------

func hash(s string) string {
	h := fnv.New32a()
	h.Write([]byte(s))
	return strconv.Itoa(int(h.Sum32()))
}

func getVolumeId(volume *libvirt.StorageVol) (string, error) {
	volumeName, err := volume.GetName()
	if err != nil {
		return "", fmt.Errorf("Failed to get volume name : %s", err.Error())
	}

	return hash(volumeName), nil
}

func getAttachmentId(volume *libvirt.StorageVol, domain *libvirt.Domain) (string, error) {
	volumeName, err := volume.GetName()
	if err != nil {
		return "", fmt.Errorf("Failed to get volume name : %s", err.Error())
	}
	domainName, err := domain.GetName()
	if err != nil {
		return "", fmt.Errorf("Failed to get volume name : %s", err.Error())
	}

	return hash(volumeName) + "-" + hash(domainName), nil
}

func GetLibvirtVolume(ref string, libvirtService *libvirt.Connect) (*libvirt.StorageVol, error) {
	storagePools, err := libvirtService.ListAllStoragePools(3)
	if err != nil {
		return nil, fmt.Errorf("Failed to list all storagePools : %s", err.Error())
	}

	for _, storagePool := range storagePools {
		libvirtVolumes, err := storagePool.ListAllStorageVolumes(0)
		if err != nil {
			return nil, fmt.Errorf("Failed to list all storages volumes : %s", err.Error())
		}
		for _, libvirtVolume := range libvirtVolumes {
			name, err := libvirtVolume.GetName()
			if err != nil {
				return nil, fmt.Errorf("Failed to get volume name : %s", err.Error())
			}
			if hash, _ := getVolumeId(&libvirtVolume); ref == hash || ref == name {
				return &libvirtVolume, nil
			}
		}
	}

	return nil, fmt.Errorf("No volume with identifier %s found", ref)
}

func getVolumeFromLibvirtVolume(libvirtVolume *libvirt.StorageVol) (*model.Volume, error) {
	volume := model.NewVolume()

	volumeXML, err := libvirtVolume.GetXMLDesc(0)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Failed get xml description of the volume : %s", err.Error()))
	}
	volumeDescription := &libvirtxml.StorageVolume{}
	err = xml.Unmarshal([]byte(volumeXML), volumeDescription)

	hash, err := getVolumeId(libvirtVolume)
	if err != nil {
		return nil, fmt.Errorf("Failed to hash the volume : %s", err.Error())
	}

	volume.Name = volumeDescription.Name
	volume.Size = int(volumeDescription.Capacity.Value / 1024 / 1024 / 1024)
	//volume.Speed =
	// TODO find a way to generate an UUID from string (no UUID given to a volume by libvirt)
	volume.ID = hash
	//volume.State =

	return volume, nil
}

func getAttachmentFromVolumeAndDomain(volume *libvirt.StorageVol, domain *libvirt.Domain) (*model.VolumeAttachment, error) {
	attachment := &model.VolumeAttachment{}

	domainXML, err := domain.GetXMLDesc(0)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Failed get xml description of the domain : %s", err.Error()))
	}
	domainDescription := &libvirtxml.Domain{}
	err = xml.Unmarshal([]byte(domainXML), domainDescription)

	volumeXML, err := volume.GetXMLDesc(0)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Failed get xml description of the domain : %s", err.Error()))
	}
	volumeDescription := &libvirtxml.StorageVolume{}
	err = xml.Unmarshal([]byte(volumeXML), volumeDescription)

	//----ID----
	id, err := getAttachmentId(volume, domain)
	if err != nil {
		return nil, fmt.Errorf("Failed to hash attachement : %s", err.Error())
	}
	attachment.ID = id

	//----Name----
	for _, disk := range domainDescription.Devices.Disks {
		splittedPath := strings.Split(disk.Source.File.File, "/")
		diskName := splittedPath[len(splittedPath)-1]
		if volumeDescription.Name == diskName {
			attachment.Name = domainDescription.Name + "-" + volumeDescription.Name
		}
	}
	if attachment.Name == "" {
		return nil, fmt.Errorf("No attachments found")
	}

	//----VolumeID----
	volumeID, err := getVolumeId(volume)
	if err != nil {
		return nil, fmt.Errorf("Failed to hash volume : %s", err.Error())
	}
	attachment.VolumeID = volumeID

	//----ServerID----
	ServerID, err := domain.GetUUIDString()
	if err != nil {
		return nil, fmt.Errorf("Failed to get UUID from domain : %s", err.Error())
	}
	attachment.ServerID = ServerID

	//----Device----
	attachment.Device = "not implemented"

	//----MountPoint----
	attachment.MountPoint = "not implemented"

	//----Format----
	attachment.Format = "not implemented"

	return attachment, nil
}

//-------------Volumes Management---------------------------------------------------------------------------------------

// CreateVolume creates a block volume
// - name is the name of the volume
// - size is the size of the volume in GB
// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
func (client *Client) CreateVolume(request model.VolumeRequest) (*model.Volume, error) {
	//volume speed is ignored

	storagePools, err := client.LibvirtService.ListAllStoragePools(3)
	if err != nil {
		return nil, fmt.Errorf("Failed to list all storagePools : %s", err.Error())
	}
	var freeStoragePool *libvirt.StoragePool
	for _, storagePool := range storagePools {
		info, err := storagePool.GetInfo()
		if err != nil {
			return nil, fmt.Errorf("Failed to get storagePool name : %s", err.Error())
		}

		if info.Available > uint64(request.Size)*1024*1024*1024 {
			freeStoragePool = &storagePool
			break
		}
	}

	if freeStoragePool == nil {
		return nil, fmt.Errorf("Free disk space is not sufficient to create a new volume")
	}

	freeStoragePoolXML, err := freeStoragePool.GetXMLDesc(0)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Failed get xml description of the storage pool : %s", err.Error()))
	}
	storagePoolDescription := &libvirtxml.StoragePool{}
	err = xml.Unmarshal([]byte(freeStoragePoolXML), storagePoolDescription)

	requestXML := `
	<volume>
		<name>` + request.Name + `</name>
		<allocation>0</allocation>
		<capacity unit="G">` + strconv.Itoa(request.Size) + `</capacity>
		<target>
			<path>` + storagePoolDescription.Target.Path + `</path>
        </target>
	</volume>`

	libvirtVolume, err := freeStoragePool.StorageVolCreateXML(requestXML, 0)
	if err != nil {
		return nil, fmt.Errorf("Failed to create the volume %s on pool %s : %s", request.Name, storagePoolDescription.Name, err.Error())
	}

	volume, err := getVolumeFromLibvirtVolume(libvirtVolume)
	if err != nil {
		return nil, fmt.Errorf("Failed to get model.Volume form libvirt.Volume %s on pool %s : %s", request.Name, storagePoolDescription.Name, err.Error())
	}

	return volume, nil
}

// GetVolume returns the volume identified by id
func (client *Client) GetVolume(ref string) (*model.Volume, error) {
	libvirtVolume, err := GetLibvirtVolume(ref, client.LibvirtService)
	if err != nil {
		return nil, fmt.Errorf("Failed to get the libvirt.Volume from ref : %s", err.Error())
	}

	volume, err := getVolumeFromLibvirtVolume(libvirtVolume)
	if err != nil {
		return nil, fmt.Errorf("Failed to get model.volume from libvirt.Volume : %s", err.Error())
	}

	return volume, nil
}

//ListVolumes return the list of all volume known on the current tenant (all=ture)
//or 'only' thode monitored by safescale (all=false) ie those monitored by metadata
func (client *Client) ListVolumes() ([]model.Volume, error) {
	storagePools, err := client.LibvirtService.ListAllStoragePools(3)
	if err != nil {
		return nil, fmt.Errorf("Failed to list all storagePools : %s", err.Error())
	}

	var volumes []model.Volume
	for _, storagePool := range storagePools {
		libvirtVolumes, err := storagePool.ListAllStorageVolumes(0)
		if err != nil {
			return nil, fmt.Errorf("Failed to list all storages volumes : %s", err.Error())
		}
		for _, libvirtVolume := range libvirtVolumes {
			volume, err := getVolumeFromLibvirtVolume(&libvirtVolume)
			if err != nil {
				return nil, fmt.Errorf("Failed to get model.Valume from libvirt.Volume : %s", err.Error())
			}
			volumes = append(volumes, *volume)
		}
	}

	return volumes, nil
}

// DeleteVolume deletes the volume identified by id
func (client *Client) DeleteVolume(ref string) error {
	libvirtVolume, err := GetLibvirtVolume(ref, client.LibvirtService)
	if err != nil {
		return fmt.Errorf("Failed to get the libvirt.Volume from ref : %s", err.Error())
	}

	err = libvirtVolume.Delete(0)
	if err != nil {
		return fmt.Errorf("Failed to delete volume %s : %s", ref, err.Error())
	}

	return nil
}

// CreateVolumeAttachment attaches a volume to an host
// - 'name' of the volume attachment
// - 'volume' to attach
// - 'host' on which the volume is attached
func (client *Client) CreateVolumeAttachment(request model.VolumeAttachmentRequest) (string, error) {
	_, domain, err := client.getHostAndDomainFromRef(request.HostID)
	if err != nil {
		return "", fmt.Errorf("Failed to get domain from request.HostID : %s", err.Error())
	}
	domainXML, err := domain.GetXMLDesc(0)
	if err != nil {
		return "", fmt.Errorf(fmt.Sprintf("Failed get xml description of the volume : %s", err.Error()))
	}
	domainDescription := &libvirtxml.Domain{}
	err = xml.Unmarshal([]byte(domainXML), domainDescription)

	libvirtVolume, err := GetLibvirtVolume(request.VolumeID, client.LibvirtService)
	if err != nil {
		return "", fmt.Errorf("Failed to get the libvirt.Volume from ref : %s", err.Error())
	}
	volumeXML, err := libvirtVolume.GetXMLDesc(0)
	if err != nil {
		return "", fmt.Errorf(fmt.Sprintf("Failed get xml description of the volume : %s", err.Error()))
	}
	volumeDescription := &libvirtxml.StorageVolume{}
	err = xml.Unmarshal([]byte(volumeXML), volumeDescription)

	diskNames := []string{}
	for _, disk := range domainDescription.Devices.Disks {
		diskNames = append(diskNames, disk.Target.Dev)
	}
	sort.Strings(diskNames)
	lastDiskName := diskNames[len(diskNames)-1]
	tmpInt, err := strconv.ParseInt(lastDiskName, 36, 64)
	newDiskName := strconv.FormatInt(tmpInt+1, 36)
	newDiskName = strings.Replace(newDiskName, "0", "a", -1)
	//TODO not working for a name only made of z (ex: 'zzz' will became '1aaa')

	requestXML := `
	<disk type='file' device='disk'>
		<source volume='' file='` + volumeDescription.Target.Path + `'/>
		<target dev='` + newDiskName + `' bus='virtio'/>
	</disk>`

	err = domain.AttachDevice(requestXML)
	if err != nil {
		return "", fmt.Errorf("Failed to attach the device to the domain : %s", err.Error())
	}

	attachment, err := getAttachmentFromVolumeAndDomain(libvirtVolume, domain)
	if err != nil {
		return "", fmt.Errorf("Faild to get attachment from domain and volume : %s", err.Error())
	}

	return attachment.ID, nil
}

// GetVolumeAttachment returns the volume attachment identified by id
func (client *Client) GetVolumeAttachment(serverID, id string) (*model.VolumeAttachment, error) {
	_, domain, err := client.getHostAndDomainFromRef(serverID)
	if err != nil {
		return nil, fmt.Errorf("Failed to get domain from ref : %s", err.Error())
	}

	libvirtVolume, err := GetLibvirtVolume(strings.Split(id, "-")[0], client.LibvirtService)
	if err != nil {
		return nil, fmt.Errorf("Failed to get the libvirt.Volume from ref : %s", err.Error())
	}

	attachment, err := getAttachmentFromVolumeAndDomain(libvirtVolume, domain)
	if err != nil {
		return nil, fmt.Errorf("Faild to get attachment from domain and volume : %s", err.Error())
	}

	return attachment, nil
}

// DeleteVolumeAttachment ...
func (client *Client) DeleteVolumeAttachment(serverID, id string) error {
	_, domain, err := client.getHostAndDomainFromRef(serverID)
	if err != nil {
		return fmt.Errorf("Failed to get domain from ref : %s", err.Error())
	}

	libvirtVolume, err := GetLibvirtVolume(strings.Split(id, "-")[0], client.LibvirtService)
	if err != nil {
		return fmt.Errorf("Failed to get the libvirt.Volume from ref : %s", err.Error())
	}

	domainXML, err := domain.GetXMLDesc(0)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("Failed get xml description of the domain : %s", err.Error()))
	}
	domainDescription := &libvirtxml.Domain{}
	err = xml.Unmarshal([]byte(domainXML), domainDescription)

	volumeXML, err := libvirtVolume.GetXMLDesc(0)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("Failed get xml description of the domain : %s", err.Error()))
	}
	volumeDescription := &libvirtxml.StorageVolume{}
	err = xml.Unmarshal([]byte(volumeXML), volumeDescription)

	for _, disk := range domainDescription.Devices.Disks {
		splittedPath := strings.Split(disk.Source.File.File, "/")
		diskName := splittedPath[len(splittedPath)-1]
		if volumeDescription.Name == diskName {
			requestXML := `
			<disk type='file' device='disk'>
				<source file='` + disk.Source.File.File + `'/>
				<target dev='` + disk.Target.Dev + `' bus='` + disk.Target.Bus + `'/>
			</disk>`
			err = domain.DetachDevice(requestXML)
			if err != nil {
				return err
			}
			return nil
		}
	}

	return fmt.Errorf(fmt.Sprintf("No attachment found to deletion"))
}

// ListVolumeAttachments lists available volume attachment
func (client *Client) ListVolumeAttachments(serverID string) ([]model.VolumeAttachment, error) {
	var volumes []*libvirt.StorageVol
	var volumeAttachments []model.VolumeAttachment

	_, domain, err := client.getHostAndDomainFromRef(serverID)
	if err != nil {
		return nil, fmt.Errorf("Failed to get domain from ref : %s", err.Error())
	}

	domainXML, err := domain.GetXMLDesc(0)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Failed get xml description of the domain : %s", err.Error()))
	}
	domainDescription := &libvirtxml.Domain{}
	err = xml.Unmarshal([]byte(domainXML), domainDescription)

	for _, disk := range domainDescription.Devices.Disks {
		split := strings.Split(disk.Source.File.File, "/")
		diskName := split[len(split)-1]
		if strings.Split(diskName, "-")[0] == "volume" {
			volume, err := GetLibvirtVolume(diskName, client.LibvirtService)
			if err != nil {
				return nil, fmt.Errorf("Failed to get volume : %s", err.Error())
			}
			volumes = append(volumes, volume)
		}
	}

	for _, volume := range volumes {
		volumeAttachment, err := getAttachmentFromVolumeAndDomain(volume, domain)
		if err != nil {
			return nil, fmt.Errorf("Failed to get Attachment from volume and domain : %s", err.Error())
		}
		volumeAttachments = append(volumeAttachments, *volumeAttachment)
	}

	return volumeAttachments, nil
}
