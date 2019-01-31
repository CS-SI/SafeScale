//+build libvirt

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
	log "github.com/sirupsen/logrus"
	"hash/fnv"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeState"
	libvirt "github.com/libvirt/libvirt-go"
	libvirtxml "github.com/libvirt/libvirt-go-xml"
)

//-------------Utils----------------------------------------------------------------------------------------------------

func hash(s string) string {
	h := fnv.New32a()
	h.Write([]byte(s))
	return strconv.Itoa(int(h.Sum32()))
}

func getVolumeID(volume *libvirt.StorageVol) (string, error) {
	volumeName, err := volume.GetName()
	if err != nil {
		return "", fmt.Errorf("Failed to get volume name : %s", err.Error())
	}

	return hash(volumeName), nil
}

func getAttachmentID(volume *libvirt.StorageVol, domain *libvirt.Domain) (string, error) {
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

func (client *Client) getStoragePoolByPath(path string) (*libvirt.StoragePool, error) {
	storagePools, err := client.LibvirtService.ListAllStoragePools(3)
	if err != nil {
		return nil, fmt.Errorf("Failed to list all storagePools : %s", err.Error())
	}

	for _, storagePool := range storagePools {
		storagePoolXML, err := storagePool.GetXMLDesc(0)
		if err != nil {
			return nil, fmt.Errorf(fmt.Sprintf("Failed get xml description of the storage pool : %s", err.Error()))
		}
		storagePoolDescription := &libvirtxml.StoragePool{}
		err = xml.Unmarshal([]byte(storagePoolXML), storagePoolDescription)

		if storagePoolDescription.Target.Path == strings.TrimRight(path, "/") {
			return &storagePool, nil
		}
	}

	return nil, fmt.Errorf("No matching storage pool found")
}

func (client *Client) CreatePoolIfUnexistant(path string) error {
	_, err := client.getStoragePoolByPath(client.Config.LibvirtStorage)
	if err != nil {
		requestXML := `
		<pool type="dir">
			<name>` + filepath.Base(path) + `</name>
			<target>
		  		<path>` + path + `</path>
			</target>
		</pool>`
		_, err = client.LibvirtService.StoragePoolCreateXML(requestXML, 0)
		if err != nil {
			return fmt.Errorf("Failed to create pool with path %s : %s", path, err.Error())
		}
	}
	return nil
}

func (client *Client) getLibvirtVolume(ref string) (*libvirt.StorageVol, error) {
	storagePool, err := client.getStoragePoolByPath(client.Config.LibvirtStorage)
	if err != nil {
		return nil, fmt.Errorf("Failed to get storage pool from path : %s", err.Error())
	}

	libvirtVolumes, err := storagePool.ListAllStorageVolumes(0)
	if err != nil {
		return nil, fmt.Errorf("Failed to list all storages volumes : %s", err.Error())
	}
	for _, libvirtVolume := range libvirtVolumes {
		name, err := libvirtVolume.GetName()
		if err != nil {
			return nil, fmt.Errorf("Failed to get volume name : %s", err.Error())
		}
		if hash, _ := getVolumeID(&libvirtVolume); ref == hash || ref == name {
			return &libvirtVolume, nil
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

	hash, err := getVolumeID(libvirtVolume)
	if err != nil {
		return nil, fmt.Errorf("Failed to hash the volume : %s", err.Error())
	}

	volume.Name = volumeDescription.Name
	volume.Size = int(volumeDescription.Capacity.Value / 1024 / 1024 / 1024)
	volume.Speed = VolumeSpeed.HDD
	volume.ID = hash
	volume.State = VolumeState.AVAILABLE

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
	id, err := getAttachmentID(volume, domain)
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
	volumeID, err := getVolumeID(volume)
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
	log.Debug("local.Client.CreateVolume() called")
	defer log.Debug("local.Client.CreateVolume() done")

	//volume speed is ignored
	storagePool, err := client.getStoragePoolByPath(client.Config.LibvirtStorage)
	if err != nil {
		return nil, fmt.Errorf("Failed to get storage pool from path : %s", err.Error())
	}

	info, err := storagePool.GetInfo()
	if err != nil {
		return nil, fmt.Errorf("Failed to get storagePool name : %s", err.Error())
	}

	if info.Available < uint64(request.Size)*1024*1024*1024 {
		return nil, fmt.Errorf("Free disk space is not sufficient to create a new volume, only %f GB left", float32(info.Available)/1024/1024/1024)
	}

	storagePoolXML, err := storagePool.GetXMLDesc(0)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Failed get xml description of the storage pool : %s", err.Error()))
	}
	storagePoolDescription := &libvirtxml.StoragePool{}
	err = xml.Unmarshal([]byte(storagePoolXML), storagePoolDescription)

	requestXML := `
	<volume>
		<name>` + request.Name + `</name>
		<allocation>0</allocation>
		<capacity unit="G">` + strconv.Itoa(request.Size) + `</capacity>
		<target>
			<path>` + storagePoolDescription.Target.Path + `</path>
        </target>
	</volume>`

	libvirtVolume, err := storagePool.StorageVolCreateXML(requestXML, 0)
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
	log.Debug("local.Client.GetVolume() called")
	defer log.Debug("local.Client.GetVolume() done")

	libvirtVolume, err := client.getLibvirtVolume(ref)
	if err != nil {
		return nil, fmt.Errorf("Failed to get the libvirt.Volume from ref : %s", err.Error())
	}

	volume, err := getVolumeFromLibvirtVolume(libvirtVolume)
	if err != nil {
		return nil, fmt.Errorf("Failed to get model.volume from libvirt.Volume : %s", err.Error())
	}

	return volume, nil
}

//ListVolumes return the list of all volume known on the current tenant
func (client *Client) ListVolumes() ([]model.Volume, error) {
	log.Debug("local.Client.ListVolumes() called")
	defer log.Debug("local.Client.ListVolumes() done")

	storagePool, err := client.getStoragePoolByPath(client.Config.LibvirtStorage)
	if err != nil {
		return nil, fmt.Errorf("Failed to get storage pool from path : %s", err.Error())
	}

	var volumes []model.Volume
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

	return volumes, nil
}

// DeleteVolume deletes the volume identified by id
func (client *Client) DeleteVolume(ref string) error {
	log.Debug("local.Client.DeleteVolume() called")
	defer log.Debug("local.Client.DeleteVolume() done")

	libvirtVolume, err := client.getLibvirtVolume(ref)
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
	log.Debug("local.Client.CreateVolumeAttachment() called")
	defer log.Debug("local.Client.CreateVolumeAttachment() done")

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

	libvirtVolume, err := client.getLibvirtVolume(request.VolumeID)
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
	log.Debug("local.Client.GetVolumeAttachment() called")
	defer log.Debug("local.Client.GetVolumeAttachment() done")

	_, domain, err := client.getHostAndDomainFromRef(serverID)
	if err != nil {
		return nil, fmt.Errorf("Failed to get domain from ref : %s", err.Error())
	}

	libvirtVolume, err := client.getLibvirtVolume(strings.Split(id, "-")[0])
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
	log.Debug("local.Client.DeleteVolumeAttachment() called")
	defer log.Debug("local.Client.DeleteVolumeAttachment() done")

	_, domain, err := client.getHostAndDomainFromRef(serverID)
	if err != nil {
		return fmt.Errorf("Failed to get domain from ref : %s", err.Error())
	}

	libvirtVolume, err := client.getLibvirtVolume(strings.Split(id, "-")[0])
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
	log.Debug("local.Client.ListVolumeAttachments() called")
	defer log.Debug("local.Client.ListVolumeAttachments() done")

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

		if strings.Split(diskName, ".")[0] != domainDescription.Name {
			volume, err := client.getLibvirtVolume(diskName)
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
