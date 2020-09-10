// +build libvirt

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
    "path/filepath"
    "sort"
    "strconv"
    "strings"

    "github.com/libvirt/libvirt-go"
    libvirtxml "github.com/libvirt/libvirt-go-xml"

    "github.com/CS-SI/SafeScale/lib/server/resources/abstract"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/volumestate"
    "github.com/CS-SI/SafeScale/lib/utils/fail"
)

// -------------Utils----------------------------------------------------------------------------------------------------

func hash(s string) string {
    h := fnv.New32a()
    _, _ = h.Write([]byte(s))
    return strconv.Itoa(int(h.Sum32()))
}

func getVolumeID(volume *libvirt.StorageVol) (string, fail.Error) {
    volumeName, err := volume.Name()
    if err != nil {
        return "", fail.Wrap(err, "failed to get volume name")
    }

    return hash(volumeName), nil
}

func getAttachmentID(volume *libvirt.StorageVol, domain *libvirt.Domain) (string, fail.Error) {
    volumeName, err := volume.Name()
    if err != nil {
        return "", fail.Wrap(err, "failed to get volume name")
    }
    domainName, err := domain.Name()
    if err != nil {
        return "", fail.Wrap(err, "failed to get volume name")
    }

    return hash(volumeName) + "-" + hash(domainName), nil
}

func (s *Stack) getStoragePoolByPath(path string) (*libvirt.StoragePool, fail.Error) {
    storagePools, err := s.LibvirtService.ListAllStoragePools(3)
    if err != nil {
        return nil, fail.Wrap(err, "failed to list all storagePools")
    }

    for _, storagePool := range storagePools {
        storagePoolXML, err := storagePool.GetXMLDesc(0)
        if err != nil {
            return nil, fail.Wrap(err, "failed get xml description of the storage pool")
        }
        storagePoolDescription := &libvirtxml.StoragePool{}
        err = xml.Unmarshal([]byte(storagePoolXML), storagePoolDescription)

        if storagePoolDescription.Target.Path == strings.TrimRight(path, "/") {
            return &storagePool, nil
        }
    }

    return nil, fail.NotFoundError("no matching storage pool found")
}

func (s *Stack) CreatePoolIfUnexistant(path string) fail.Error {
    _, err := s.getStoragePoolByPath(s.LibvirtConfig.LibvirtStorage)
    if err != nil {
        requestXML := `
		 <pool type="dir">
			 <name>` + filepath.Base(path) + `</name>
			 <target>
				   <path>` + path + `</path>
			 </target>
		 </pool>`
        _, err = s.LibvirtService.StoragePoolCreateXML(requestXML, 0)
        if err != nil {
            return fail.Wrap(err, "failed to create pool with path '%s'")
        }
    }
    return nil
}

func (s *Stack) getLibvirtVolume(ref string) (*libvirt.StorageVol, fail.Error) {
    storagePool, err := s.getStoragePoolByPath(s.LibvirtConfig.LibvirtStorage)
    if err != nil {
        return nil, fail.Wrap(err, "failed to get storage pool from path")
    }

    libvirtVolumes, err := storagePool.ListAllStorageVolumes(0)
    if err != nil {
        return nil, fail.Wrap(err, "failed to list all storages volumes")
    }
    for _, libvirtVolume := range libvirtVolumes {
        name, err := libvirtVolume.Name()
        if err != nil {
            return nil, fail.Wrap(err, "failed to get volume name")
        }
        if hash, _ := getVolumeID(&libvirtVolume); ref == hash || ref == name {
            return &libvirtVolume, nil
        }
    }

    return nil, abstract.ResourceNotFoundError("volume", ref)
}

func getVolumeFromLibvirtVolume(libvirtVolume *libvirt.StorageVol) (*abstract.Volume, fail.Error) {
    volume := abstract.NewVolume()

    volumeXML, err := libvirtVolume.GetXMLDesc(0)
    if err != nil {
        return nil, fail.Wrap(err, "failed get xml description of the volume")
    }
    volumeDescription := &libvirtxml.StorageVolume{}
    err = xml.Unmarshal([]byte(volumeXML), volumeDescription)

    hash, err := getVolumeID(libvirtVolume)
    if err != nil {
        return nil, fail.Wrap(err, "failed to hash the volume")
    }

    volume.Name = volumeDescription.Name
    volume.Size = int(volumeDescription.Capacity.Value / 1024 / 1024 / 1024)
    volume.Speed = volumespeed.HDD
    volume.ID = hash
    volume.State = volumestate.AVAILABLE

    return volume, nil
}

func getAttachmentFromVolumeAndDomain(volume *libvirt.StorageVol, domain *libvirt.Domain) (*abstract.VolumeAttachment, fail.Error) {
    attachment := &abstract.VolumeAttachment{}

    domainXML, err := domain.GetXMLDesc(0)
    if err != nil {
        return nil, fail.Wrap(err, "failed get xml description of the domain")
    }
    domainDescription := &libvirtxml.Domain{}
    err = xml.Unmarshal([]byte(domainXML), domainDescription)

    volumeXML, err := volume.GetXMLDesc(0)
    if err != nil {
        return nil, fail.Wrap(err, "failed get xml description of the domain")
    }
    volumeDescription := &libvirtxml.StorageVolume{}
    err = xml.Unmarshal([]byte(volumeXML), volumeDescription)

    // ----ID----
    id, err := getAttachmentID(volume, domain)
    if err != nil {
        return nil, fail.Wrap(err, "failed to hash attachement")
    }
    attachment.ID = id

    // ----Name----
    for _, disk := range domainDescription.Devices.Disks {
        splittedPath := strings.Split(disk.Source.File.File, "/")
        diskName := splittedPath[len(splittedPath)-1]
        if volumeDescription.Name == diskName {
            attachment.Name = domainDescription.Name + "-" + volumeDescription.Name
        }
    }
    if attachment.Name == "" {
        return nil, fail.NotFoundError("no attachments found")
    }

    // ----VolumeID----
    volumeID, err := getVolumeID(volume)
    if err != nil {
        return nil, fail.Wrap(err, "failed to hash volume")
    }
    attachment.VolumeID = volumeID

    // ----ServerID----
    ServerID, err := domain.GetUUIDString()
    if err != nil {
        return nil, fail.Wrap(err, "failed to get UUID from domain")
    }
    attachment.ServerID = ServerID

    // ----Device----
    attachment.Device = "not implemented"

    // ----MountPoint----
    attachment.MountPoint = "not implemented"

    // ----Format----
    attachment.Format = "not implemented"

    return attachment, nil
}

// -------------Volumes Management---------------------------------------------------------------------------------------

// CreateVolume creates a block volume
// - name is the name of the volume
// - size is the size of the volume in GB
// - volumeType is the type of volume to create, if volumeType is empty the driver use a default type
func (s *Stack) CreateVolume(request abstract.VolumeRequest) (*abstract.Volume, fail.Error) {
    // FIXME: validate parameters
    defer debug.NewTracer(nil, fmt.Sprintf("('%s',%d)", request.Name, request.Size), true).Entering().Exiting()

    // volume speed is ignored
    storagePool, err := s.getStoragePoolByPath(s.LibvirtConfig.LibvirtStorage)
    if err != nil {
        return nil, fail.Wrap(err, "failed to get storage pool from path")
    }

    info, err := storagePool.GetInfo()
    if err != nil {
        return nil, fail.Wrap(err, "failed to get storagePool name")
    }

    if info.Available < uint64(request.Size)*1024*1024*1024 {
        return nil, fail.OverflowError(info.Available, nil, "free disk space is not sufficient to create a new volume, only %f GB left", float32(info.Available)/1024/1024/1024)
    }

    storagePoolXML, err := storagePool.GetXMLDesc(0)
    if err != nil {
        return nil, fail.Wrap(err, "failed get xml description of the storage pool")
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
        return nil, fail.Wrap(err, "failed to create the volume '%s' on pool '%s'", request.Name, storagePoolDescription.Name)
    }

    volume, err := getVolumeFromLibvirtVolume(libvirtVolume)
    if err != nil {
        return nil, fail.Wrap(err, "failed to convert libvirt.Volume '%s' to abstract.Volume on pool '%s'", request.Name, storagePoolDescription.Name)
    }

    return volume, nil
}

// InspectVolume returns the volume identified by id
func (s *Stack) InspectVolume(ref string) (*abstract.Volume, fail.Error) {
    // FIXME: validate parameters
    defer debug.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).Entering().Exiting()

    libvirtVolume, err := s.getLibvirtVolume(ref)
    if err != nil {
        return nil, err
    }

    volume, err := getVolumeFromLibvirtVolume(libvirtVolume)
    if err != nil {
        return nil, fail.Wrap(err, "failed to get abstract.volume from libvirt.Volume")
    }

    return volume, nil
}

// ListVolumes return the list of all volume known on the current tenant
func (s *Stack) ListVolumes() ([]abstract.Volume, fail.Error) {
    // FIXME: validate parameters
    defer debug.NewTracer(nil, "", true).Entering().Exiting()

    storagePool, err := s.getStoragePoolByPath(s.LibvirtConfig.LibvirtStorage)
    if err != nil {
        return nil, fail.Wrap(err, "failed to get storage pool from path")
    }

    var volumes []abstract.Volume
    libvirtVolumes, err := storagePool.ListAllStorageVolumes(0)
    if err != nil {
        return nil, fail.Wrap(err, "failed to list all storages volumes")
    }
    for _, libvirtVolume := range libvirtVolumes {
        volume, err := getVolumeFromLibvirtVolume(&libvirtVolume)
        if err != nil {
            return nil, fail.Wrap(err, "failed to get abstract.Valume from libvirt.Volume")
        }
        volumes = append(volumes, *volume)
    }

    return volumes, nil
}

// DeleteVolume deletes the volume identified by id
func (s *Stack) DeleteVolume(ref string) fail.Error {
    // FIXME: validate parameters
    defer debug.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).Entering().Exiting()

    libvirtVolume, err := s.getLibvirtVolume(ref)
    if err != nil {
        return err
    }

    err = libvirtVolume.Delete(0)
    if err != nil {
        return fail.Wrap(err, "failed to delete volume '%s'", ref)
    }

    return nil
}

// CreateVolumeAttachment attaches a volume to an host
// - 'name' of the volume attachment
// - 'volume' to attach
// - 'host' on which the volume is attached
func (s *Stack) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, fail.Error) {
    // FIXME: validate parameters
    defer debug.NewTracer(nil, fmt.Sprintf("('%s', '%s', '%s'", request.Name, request.VolumeID, request.HostID), true).Entering().Exiting()

    _, domain, err := s.getHostAndDomainFromRef(request.HostID)
    if err != nil {
        return "", fail.Wrap(err, "failed to get domain from request.HostID")
    }
    domainXML, err := domain.GetXMLDesc(0)
    if err != nil {
        return "", fail.Wrap(err, "failed get xml description of the volume")
    }
    domainDescription := &libvirtxml.Domain{}
    err = xml.Unmarshal([]byte(domainXML), domainDescription)

    libvirtVolume, err := s.getLibvirtVolume(request.VolumeID)
    if err != nil {
        return "", err
    }
    volumeXML, err := libvirtVolume.GetXMLDesc(0)
    if err != nil {
        return "", fail.Wrap("failed get xml description of the volume")
    }
    volumeDescription := &libvirtxml.StorageVolume{}
    err = xml.Unmarshal([]byte(volumeXML), volumeDescription)

    var diskNames []string
    for _, disk := range domainDescription.Devices.Disks {
        diskNames = append(diskNames, disk.Target.Dev)
    }
    sort.Strings(diskNames)
    lastDiskName := diskNames[len(diskNames)-1]
    tmpInt, err := strconv.ParseInt(lastDiskName, 36, 64)
    newDiskName := strconv.FormatInt(tmpInt+1, 36)
    newDiskName = strings.Replace(newDiskName, "0", "a", -1)
    // TODO not working for a name only made of z (ex: 'zzz' will became '1aaa')

    requestXML := `
 <disk type='file' device='disk'>
	 <source volume='' file='` + volumeDescription.Target.Path + `'/>
	 <target dev='` + newDiskName + `' bus='virtio'/>
 </disk>`

    err = domain.AttachDevice(requestXML)
    if err != nil {
        return "", fail.Wrap(err, "failed to attach the device to the domain")
    }

    attachment, err := getAttachmentFromVolumeAndDomain(libvirtVolume, domain)
    if err != nil {
        return "", fail.Wrap(err, "failed to get attachment from domain and volume")
    }

    return attachment.ID, nil
}

// GetVolumeAttachment returns the volume attachment identified by id
func (s *Stack) GetVolumeAttachment(serverID, id string) (*abstract.VolumeAttachment, fail.Error) {
    // FIXME: validate parameters
    defer debug.NewTracer(nil, fmt.Sprintf("('%s', '%s')", serverID, id), true).Entering().Exiting()

    _, domain, err := s.getHostAndDomainFromRef(serverID)
    if err != nil {
        return nil, fail.Wrap(err, "failed to get domain from ref")
    }

    libvirtVolume, err := s.getLibvirtVolume(strings.Split(id, "-")[0])
    if err != nil {
        return nil, err
    }

    attachment, err := getAttachmentFromVolumeAndDomain(libvirtVolume, domain)
    if err != nil {
        return nil, fail.Wrap(err, "failed to get attachment from domain and volume")
    }

    return attachment, nil
}

// DeleteVolumeAttachment ...
func (s *Stack) DeleteVolumeAttachment(serverID, id string) fail.Error {
    // FIXME: validate parameters
    defer debug.NewTracer(nil, fmt.Sprintf("('%s', '%s')", serverID, id), true).Entering().Exiting()

    _, domain, err := s.getHostAndDomainFromRef(serverID)
    if err != nil {
        return fail.Wrap(err, "failed to get domain from ref")
    }

    libvirtVolume, err := s.getLibvirtVolume(strings.Split(id, "-")[0])
    if err != nil {
        return err
    }

    domainXML, err := domain.GetXMLDesc(0)
    if err != nil {
        return fail.Wrap(err, "failed get xml description of the domain")
    }
    domainDescription := &libvirtxml.Domain{}
    err = xml.Unmarshal([]byte(domainXML), domainDescription)

    volumeXML, err := libvirtVolume.GetXMLDesc(0)
    if err != nil {
        return fail.Wrap(err, "failed get xml description of the volume")
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

    return fail.NotFoundError("failed to find volume attachment to delete")
}

// ListVolumeAttachments lists available volume attachment
func (s *Stack) ListVolumeAttachments(serverID string) ([]abstract.VolumeAttachment, fail.Error) {
    // FIXME: validate parameters
    defer debug.NewTracer(nil, fmt.Sprintf("('%s')", serverID), true).Entering().Exiting()

    var volumes []*libvirt.StorageVol
    var volumeAttachments []abstract.VolumeAttachment

    _, domain, err := s.getHostAndDomainFromRef(serverID)
    if err != nil {
        return nil, fail.Wrap(err, "failed to get domain from ref")
    }

    domainXML, err := domain.GetXMLDesc(0)
    if err != nil {
        return nil, fail.Wrap(err, "failed get xml description of the domain")
    }
    domainDescription := &libvirtxml.Domain{}
    err = xml.Unmarshal([]byte(domainXML), domainDescription)

    for _, disk := range domainDescription.Devices.Disks {
        split := strings.Split(disk.Source.File.File, "/")
        diskName := split[len(split)-1]

        if strings.Split(diskName, ".")[0] != domainDescription.Name {
            volume, err := s.getLibvirtVolume(diskName)
            if err != nil {
                return nil, fail.Wrap(err, "failed to get volume")
            }
            volumes = append(volumes, volume)
        }
    }

    for _, volume := range volumes {
        volumeAttachment, err := getAttachmentFromVolumeAndDomain(volume, domain)
        if err != nil {
            return nil, fail.Wrap(err, "failed to get attachment from volume and domain")
        }
        volumeAttachments = append(volumeAttachments, *volumeAttachment)
    }

    return volumeAttachments, nil
}
