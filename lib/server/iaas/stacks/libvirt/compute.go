// +build libvirt,!ignore

/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/libvirt/libvirt-go"
	libvirtxml "github.com/libvirt/libvirt-go-xml"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// The createds hosts could be connected to the network with a bridge or a nat
// CAUTION the bridged VMs needs the default route to be a macVlan interface!
// On centos the firewall bloks all ports by default so the vm will not be alble to send back useful infos
// sudo firewall-cmd --permanent --zone=public --add-port=1000-63553/tcp
// sudo firewall-cmd --reload
var bridgedVMs = false
var defaultNetworkCIDR = "192.168.122.0/24"

// # Create a macvlan interface :
// # - Script creating the macvlan
// cat <<-'EOF' > ~/ssmacvlan.sh
// #!/bin/bash
// MACVLN="ssmacvlan0"
// HWLINK=$(ip -o route | grep default | awk '{{print $5}}')
// IP=$(ip address show dev $HWLINK | grep "inet " | awk '{print $2}')
// NETWORK=$(ip -o route | grep $HWLINK | grep `echo $IP|cut -d/ -f1` | awk '{print $1}')
// GATEWAY=$(ip -o route | grep default | awk '{print $3}')

// ip link add link $HWLINK $MACVLN type macvlan mode bridge
// ip address add $IP dev $MACVLN
// ip link set dev $MACVLN up

// ip route flush dev $HWLINK
// ip route flush dev $MACVLN

// ip route add $NETWORK dev $MACVLN metric 0
// ip route add default via $GATEWAY
// EOF
// chmod u+x ~/ssmacvlan.sh
// sudo mv ~/ssmacvlan.sh /sbin/

// # - Launch the scrip on each boot
// cat <<-'EOF' > ~/ssmacvlan.service
// Description=create safescale macvlan
// After=network.target

// [Service]
// ExecStart=/sbin/ssmacvlan.sh
// Restart=on-failure
// StartLimitIntervalSec=10

// [Install]
// WantedBy=multi-user.target
// EOF
// sudo mv ~/ssmacvlan.service /etc/systemd/system/
// sudo systemctl enable ssmacvlan
// sudo systemctl start ssmacvlan

// -------------IMAGES---------------------------------------------------------------------------------------------------

// ListImages lists available OS images
func (s stack) ListImages() (images []abstract.Image, xerr fail.Error) {
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	jsonFile, err := os.Open(s.LibvirtConfig.ImagesJSONPath)
	if err != nil {
		return nil, fail.Wrap(err, "failed to open '%s'", s.LibvirtConfig.ImagesJSONPath)
	}
	defer func() {
		if err := jsonFile.Close(); err != nil {
			fmt.Println("failed to close images file")
		}
	}()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, fail.Wrap(err, "failed to read '%s'", s.LibvirtConfig.ImagesJSONPath)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(byteValue), &result); err != nil {
		return nil, fail.Wrap(err, "failed to unmarshal jsonFile '%s'", s.LibvirtConfig.ImagesJSONPath)
	}

	imagesJSON, ok := result["images"].([]interface{})
	if !ok {
		return nil, fail.InvalidParameterError("result['images']]", "is not an array")
	}
	images = []abstract.Image{}
	for _, imageJSON := range imagesJSON {
		image := abstract.Image{
			ID:   imageJSON.(map[string]interface{})["imageID"].(string),
			Name: imageJSON.(map[string]interface{})["imageName"].(string),
		}
		images = append(images, image)
	}

	return images, nil
}

// GetImage returns the Image referenced by id
func (s stack) GetImage(id string) (image *abstract.Image, xerr fail.Error) {
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	jsonFile, err := os.Open(s.LibvirtConfig.ImagesJSONPath)
	if err != nil {
		return nil, fail.Wrap(err, "failed to open %s", s.LibvirtConfig.ImagesJSONPath)
	}
	defer func() {
		if err := jsonFile.Close(); err != nil {
			logrus.Errorf("failed to close images file")
		}
	}()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, fail.Wrap(err, "failed to read %s", s.LibvirtConfig.ImagesJSONPath)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(byteValue), &result); err != nil {
		return nil, fail.Wrap(err, "failed to unmarshal jsonFile '%s'", s.LibvirtConfig.ImagesJSONPath)
	}

	imagesJSON, ok := result["images"].([]interface{})
	if !ok {
		return nil, fail.InvalidParameterError("result['images']]", "is not an array")
	}
	for _, imageJSON := range imagesJSON {
		if imageID, ok := imageJSON.(map[string]interface{})["imageID"]; ok && imageID == id {
			return &abstract.Image{
				ID:   imageJSON.(map[string]interface{})["imageID"].(string),
				Name: imageJSON.(map[string]interface{})["imageName"].(string),
			}, nil
		}
		if imageName, ok := imageJSON.(map[string]interface{})["imageName"]; ok && imageName == id {
			return &abstract.Image{
				ID:   imageJSON.(map[string]interface{})["imageID"].(string),
				Name: imageJSON.(map[string]interface{})["imageName"].(string),
			}, nil
		}
	}

	return nil, fail.NotFoundError("image with id=%s not found", id)
}

// -------------TEMPLATES------------------------------------------------------------------------------------------------

// ListTemplates overload OpenStack ListTemplate method to filter wind and flex instance and add GPU configuration
func (s stack) ListTemplates() (templates []abstract.HostTemplate, xerr fail.Error) {
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	jsonFile, err := os.Open(s.LibvirtConfig.TemplatesJSONPath)
	if err != nil {
		return nil, fail.Wrap(err, "failed to open '%s'", s.LibvirtConfig.TemplatesJSONPath)
	}
	defer func() {
		if err := jsonFile.Close(); err != nil {
			fmt.Println("failed to close template file")
		}
	}()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, fail.Wrap(err, "failed to read '%s'", s.LibvirtConfig.TemplatesJSONPath)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(byteValue), &result); err != nil {
		return nil, fail.Wrap(err, "failed to unmarshal jsonFile '%s'", s.LibvirtConfig.TemplatesJSONPath)
	}

	templatesJSON, ok := result["templates"].([]interface{})
	if !ok {
		return nil, fail.InvalidParameterError("result['templates']]", "is not an array")
	}
	templates = []abstract.HostTemplate{}
	for _, templateJSON := range templatesJSON {
		template := abstract.HostTemplate{
			Cores:     int(templateJSON.(map[string]interface{})["templateSpecs"].(map[string]interface{})["coresNumber"].(float64)),
			RAMSize:   float32(templateJSON.(map[string]interface{})["templateSpecs"].(map[string]interface{})["ramSize"].(float64)),
			DiskSize:  int(templateJSON.(map[string]interface{})["templateSpecs"].(map[string]interface{})["diskSize"].(float64)),
			GPUNumber: int(templateJSON.(map[string]interface{})["templateSpecs"].(map[string]interface{})["gpuNumber"].(float64)),
			GPUType:   templateJSON.(map[string]interface{})["templateSpecs"].(map[string]interface{})["gpuType"].(string),
			ID:        templateJSON.(map[string]interface{})["templateID"].(string),
			Name:      templateJSON.(map[string]interface{})["templateName"].(string),
		}
		templates = append(templates, template)
	}

	return templates, nil
}

// GetTemplate overload OpenStack GetTemplate method to add GPU configuration
func (s stack) GetTemplate(id string) (template *abstract.HostTemplate, xerr fail.Error) {
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	jsonFile, err := os.Open(s.LibvirtConfig.TemplatesJSONPath)
	if err != nil {
		return nil, fail.Wrap(err, "failed to open '%s'", s.LibvirtConfig.TemplatesJSONPath)
	}
	defer func() {
		if err := jsonFile.Close(); err != nil {
			fmt.Println("failed to close template file")
		}
	}()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, fail.Wrap(err, "failed to read '%s'", s.LibvirtConfig.TemplatesJSONPath)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(byteValue), &result); err != nil {
		return nil, fail.Wrap(err, "failed to unmarshal jsonFile '%s'", s.LibvirtConfig.TemplatesJSONPath)
	}

	templatesJSON, ok := result["templates"].([]interface{})
	if !ok {
		return nil, fail.InvalidParameterError("result['templates']", "is not an array")
	}
	for _, templateJSON := range templatesJSON {
		if templateID, _ := templateJSON.(map[string]interface{})["templateID"]; templateID == id {
			return &abstract.HostTemplate{
				Cores:     int(templateJSON.(map[string]interface{})["templateSpecs"].(map[string]interface{})["coresNumber"].(float64)),
				RAMSize:   float32(templateJSON.(map[string]interface{})["templateSpecs"].(map[string]interface{})["ramSize"].(float64)),
				DiskSize:  int(templateJSON.(map[string]interface{})["templateSpecs"].(map[string]interface{})["diskSize"].(float64)),
				GPUNumber: int(templateJSON.(map[string]interface{})["templateSpecs"].(map[string]interface{})["gpuNumber"].(float64)),
				GPUType:   templateJSON.(map[string]interface{})["templateSpecs"].(map[string]interface{})["gpuType"].(string),
				ID:        templateJSON.(map[string]interface{})["templateID"].(string),
				Name:      templateJSON.(map[string]interface{})["templateName"].(string),
			}, nil
		}
	}

	return nil, fail.NotFoundError("template with id '%s' not found", id)
}

// -------------SSH KEYS-------------------------------------------------------------------------------------------------

// CreateKeyPair creates and import a key pair
func (s stack) CreateKeyPair(name string) (*abstract.KeyPair, fail.Error) {
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	kp, err := abstract.NewKeyPair(name)
	if err != nil {
		return nil, err
	}

	kpid, kerr := uuid.NewV4()
	if kerr != nil {
		return nil, fail.NewError(fmt.Sprintf("failed to generate uuid key : %s", kerr.Error()), err)
	}

	kp.ID = string(kpid[:])

	return kp, nil
}

// GetKeyPair returns the key pair identified by id
func (s stack) GetKeyPair(id string) (*abstract.KeyPair, fail.Error) {
	return nil, fail.NotImplementedError("InspectKeyPair() not implemented yet") // FIXME: Technical debt
}

// ListKeyPairs lists available key pairs
func (s stack) ListKeyPairs() ([]abstract.KeyPair, fail.Error) {
	return nil, fail.NotImplementedError("ListKeyPairs() not implemented yet") // FIXME: Technical debt
}

// DeleteKeyPair deletes the key pair identified by id
func (s stack) DeleteKeyPair(id string) fail.Error {
	return fail.NotImplementedError("DeleteKeyPair() not implemented yet") // FIXME: Technical debt
}

// -------------HOST MANAGEMENT------------------------------------------------------------------------------------------
func downloadImage(path string, downloadInfo map[string]interface{}) fail.Error {
	switch downloadInfo["method"].(string) {
	case "GoogleDrive":
		command := fmt.Sprintf(`file_name="%s"
 file_id="%s"
 cookie_file="%s/cookie.txt"
 query=$(curl -c ${cookie_file} -s -L "https://drive.google.com/uc?export=download&id=${file_id}" | perl -nE'say/uc-download-link.*? href="(.*?)\">/' | sed -e 's/amp;//g' | sed -n 2p)
 url="https://drive.google.com$query"
 curl -b ${cookie_file} -L -o ${file_name} $url
 rm ${cookie_file}`, path, downloadInfo["id"].(string), filepath.Dir(path))
		cmd := exec.Command("bash", "-c", command)
		err := cmd.Run()
		if err != nil {
			return fail.Wrap(err, "command failed: '%s'\n", command)
		}
	default:
		return fail.NotImplementedError(fmt.Sprintf("download method %s not implemented", downloadInfo["method"].(string)))
	}
	return nil
}

// getImagePathFromID retrieve the storage path of an image from this image ID
func getImagePathFromID(s *Stack, id string) (path string, xerr fail.Error) {
	jsonFile, err := os.Open(s.LibvirtConfig.ImagesJSONPath)
	if err != nil {
		return "", fail.Wrap(err, "failed to open '%s'", s.LibvirtConfig.ImagesJSONPath)
	}
	defer func() {
		if err := jsonFile.Close(); err != nil {
			fmt.Println("failed to close image file")
		}
	}()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return "", fail.Wrap(err, "failed to read '%s'", s.LibvirtConfig.ImagesJSONPath)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(byteValue), &result); err != nil {
		return "", fail.Wrap(err, "failed to unmarshal jsonFile '%s'", s.LibvirtConfig.ImagesJSONPath)
	}

	imagesJSON, ok := result["images"].([]interface{})
	if !ok {
		return "", fail.InvalidParameterError("result['images']", "must be an array")
	}
	for _, imageJSON := range imagesJSON {
		if imageID, _ := imageJSON.(map[string]interface{})["imageID"]; imageID == id {
			path, ok := imageJSON.(map[string]interface{})["imagePath"].(string)
			if !ok {
				return "", fail.InvalidParameterError("imagePath", "must be an non-empty string")
			}
			// check parent directory first
			parentDir := filepath.Dir(path)
			if _, err := os.Stat(parentDir); os.IsNotExist(err) {
				if err != nil {
					return "", fail.NewError("failed to download image: directory '%s' doesn't exist", parentDir)
				}
			}
			// download if image file isn't there
			if _, err := os.Stat(path); os.IsNotExist(err) {
				downloadPath, ok := imageJSON.(map[string]interface{})["download"]
				if !ok {
					return "", fail.SyntaxError("invalid json")
				}
				mapDownload, ok := downloadPath.(map[string]interface{})
				if !ok {
					return "", fail.SyntaxError("invalid json")
				}
				err := downloadImage(path, mapDownload)
				if err != nil {
					return "", fail.Wrap(err, "failed to download image:")
				}
			} else if err != nil {
				return "", fail.Wrap(err, "unable to check if the file '%s' exists", filepath.Base(path))
			}
			return path, nil
		}
	}

	return "", fail.NotFoundError("image with id '%s' not found", id)
}

// getDiskFromID retrieve the disk with root partition of an image from this image ID
func getDiskFromID(s *Stack, id string) (disk string, xerr fail.Error) {
	jsonFile, err := os.Open(s.LibvirtConfig.ImagesJSONPath)
	if err != nil {
		return "", fail.Wrap(err, "failed to open '%s'", s.LibvirtConfig.ImagesJSONPath)
	}
	defer func() {
		if err := jsonFile.Close(); err != nil {
			fmt.Println("failed to close image file")
		}
	}()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return "", fail.Wrap(err, "failed to read '%s'", s.LibvirtConfig.ImagesJSONPath)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(byteValue), &result); err != nil {
		return "", fail.Wrap(err, "failed to unmarshal jsonFile '%s'", s.LibvirtConfig.ImagesJSONPath)
	}

	imagesJSON, ok := result["images"].([]interface{})
	if !ok {
		return "", fail.InvalidParameterError("result['images']]", "is not an array")
	}
	for _, imageJSON := range imagesJSON {
		if imageID, _ := imageJSON.(map[string]interface{})["imageID"]; imageID == id {
			return imageJSON.(map[string]interface{})["disk"].(string), nil
		}
	}

	return "", fail.NotFoundError("image with id '%s' not found", id)
}

func getVolumesFromDomain(domain *libvirt.Domain, libvirtService *libvirt.Connect) ([]*libvirtxml.StorageVolume, fail.Error) {
	var volumeDescriptions []*libvirtxml.StorageVolume
	var domainVolumePaths []string

	// List paths of domain disks
	domainXML, err := domain.GetXMLDesc(0)
	if err != nil {
		return nil, fail.Wrap(err, "failed get xml description of domain")
	}
	domainDescription := &libvirtxml.Domain{}
	err = xml.Unmarshal([]byte(domainXML), domainDescription)
	if err != nil {
		return nil, fail.Wrap(err, "failed unmarshall the domain description")
	}
	domainDisks := domainDescription.Devices.Disks

	for _, disk := range domainDisks {
		domainVolumePaths = append(domainVolumePaths, disk.Source.File.File)
	}

	// Check which volumes match these paths
	pools, err := libvirtService.ListAllStoragePools(2)
	if err != nil {
		return nil, fail.Wrap(err, "failed to list pools")
	}
	for _, pool := range pools {
		volumes, err := pool.ListAllStorageVolumes(0)
		if err != nil {
			continue
		}
		for _, volume := range volumes {
			volumeXML, err := volume.GetXMLDesc(0)
			if err != nil {
				continue
			}
			volumeDescription := &libvirtxml.StorageVolume{}
			err = xml.Unmarshal([]byte(volumeXML), volumeDescription)
			if err != nil {
				return nil, fail.Wrap(err, "failed to unmarshall the volume description")
			}

			for _, domainVolumePath := range domainVolumePaths {
				if volumeDescription.Key == domainVolumePath {
					volumeDescriptions = append(volumeDescriptions, volumeDescription)
				}
			}

		}
	}
	return volumeDescriptions, nil
}

// stateConvert convert libvirt.DomainState to a HostState.Enum
func stateConvert(stateLibvirt libvirt.DomainState) hoststate.Enum {
	switch stateLibvirt {
	case 1:
		return hoststate.STARTED
	case 3, 5:
		return hoststate.STOPPED
	case 4:
		return hoststate.STOPPING
	default:
		return hoststate.ERROR
	}
}

func getDescriptionV1FromDomain(domain *libvirt.Domain, libvirtService *libvirt.Connect) (*propertiesv1.HostDescription, fail.Error) {
	hostDescription := propertiesv1.NewHostDescription()

	// var Created time.Time
	// var Creator string
	// var Updated time.Time
	// var Purpose string

	// There is a creation and modification timestamp on disks but it'not the best way to get the vm creation / modification date

	return hostDescription, nil
}

func getSizingV1FromDomain(domain *libvirt.Domain, libvirtService *libvirt.Connect) (*propertiesv1.HostSizing, fail.Error) {
	hostSizing := propertiesv1.NewHostSizing()

	info, err := domain.GetInfo()
	if err != nil {
		return nil, fail.Wrap(err, "failed to get infos from the domain")
	}

	diskSize := 0
	volumes, err := getVolumesFromDomain(domain, libvirtService)
	if err != nil {
		return nil, fail.Wrap(err, "failed to get volumes from the domain")
	}
	for _, volume := range volumes {
		diskSize += int(volume.Capacity.Value / 1024 / 1024 / 1024)
	}

	hostSizing.AllocatedSize.RAMSize = float32(info.MaxMem) / 1024 / 1024
	hostSizing.AllocatedSize.Cores = int(info.NrVirtCpu)
	hostSizing.AllocatedSize.DiskSize = diskSize
	// TODO: GPU not implemented
	hostSizing.AllocatedSize.GPUNumber = 0
	hostSizing.AllocatedSize.GPUType = ""

	// hostSizing.RequestedSize and hostSizing.Template are unknown by libvirt and are left unset

	return hostSizing, nil
}
func (s stack) getNetworkV2FromDomain(domain *libvirt.Domain) (*propertiesv2.HostNetwork, fail.Error) {
	hostNetwork := propertiesv2.NewHostNetwork()

	domainXML, err := domain.GetXMLDesc(0)
	if err != nil {
		return nil, fail.Wrap(err, "failed get xml description of the domain")
	}
	domainDescription := &libvirtxml.Domain{}
	err = xml.Unmarshal([]byte(domainXML), domainDescription)

	networks, err := s.LibvirtService.ListAllNetworks(3)
	if err != nil {
		return nil, fail.Wrap(err, "failed to list all networks")
	}

	for _, iface := range domainDescription.Devices.Interfaces {
		if iface.Source.Network != nil {
			err = retry.WhileUnsuccessfulDelay5Seconds(
				func() error {
					for _, network := range networks {
						name, err := network.GetName()
						if err != nil {
							return fail.Wrap(err, "failed to get network name")
						}
						if name == iface.Source.Network.Network {
							dhcpLeases, err := network.GetDHCPLeases()
							if err != nil {
								return fail.Wrap(err, "failed to get network dhcpLeases")
							}
							for _, dhcpLease := range dhcpLeases {
								if dhcpLease.Mac == iface.MAC.Address {
									net, err := s.InspectNetwork(iface.Source.Network.Network)
									if err != nil {
										return fail.NotFoundError("unknown Networking %s", iface.Source.Network.Network)
									}
									if len(strings.Split(dhcpLease.IPaddr, ".")) == 4 {
										if name == "default" {
											hostNetwork.PublicIPv4 = dhcpLease.IPaddr
											return nil
										} else {
											hostNetwork.IPv4Addresses[net.ID] = dhcpLease.IPaddr
										}
									} else if len(strings.Split(dhcpLease.IPaddr, ":")) == 8 {
										if name == "default" {
											hostNetwork.PublicIPv4 = dhcpLease.IPaddr
											return nil
										} else {
											hostNetwork.IPv6Addresses[net.ID] = dhcpLease.IPaddr
										}
									} else {
										return fail.NewError("unknown adressType")
									}
									hostNetwork.NetworksByID[net.ID] = net.Name
									hostNetwork.NetworksByName[net.Name] = net.ID
									return nil
								}
							}
						}
					}
					return fail.NotFoundError("no local IP matching inteface '%s' found", iface.Alias)
				},
				temporal.GetHostTimeout(),
			)
			if err != nil {
				return nil, fail.Wrap(err, "")
			}
		}
	}
	return hostNetwork, nil
}

// getHostFromDomain build a abstract.IPAddress struct representing a Domain
func (s stack) getHostFromDomain(domain *libvirt.Domain) (_ *abstract.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	id, err := domain.GetUUIDString()
	if err != nil {
		return nil, fail.Wrap(err, "failed to fetch id from domain")
	}
	name, err := domain.GetName()
	if err != nil {
		return nil, fail.Wrap(err, "failed to fetch name from domain")
	}
	state, _, err := domain.GetState()
	if err != nil {
		return nil, fail.Wrap(err, "failed to fetch state from domain")
	}

	host := abstract.NewHostCore()

	host.ID = id
	host.Name = name
	host.PrivateKey = "Impossible to fetch them from the domain, the private key is unknown by the domain"
	host.LastState = stateConvert(state)

	return host, nil
}

// getHostAndDomainFromRef retrieve the host and the domain associated to an ref (id or name)
func (s stack) getHostAndDomainFromRef(ref string) (*abstract.HostCore, *libvirt.Domain, fail.Error) {
	domain, err := s.LibvirtService.LookupDomainByUUIDString(ref)
	if err != nil {
		domain, err = s.LibvirtService.LookupDomainByName(ref)
		if err != nil {
			re, err2 := regexp.Compile("[0-9]+")
			if err2 != nil {
				return nil, nil, fail.Wrap(err, "failed to fetch domain from ref")
			}
			errCode, _ := strconv.Atoi(re.FindString(err.Error()))
			if errCode == 42 {
				return nil, nil, abstract.ResourceNotFoundError("host", ref)
			}
			return nil, nil, fail.Wrap(err, "failed to fetch domain from ref")
		}
	}
	host, err := s.getHostFromDomain(domain)
	if err != nil {
		return nil, nil, fail.Wrap(err, "failed to get host from domain")
	}

	return host, domain, nil
}

func (s stack) complementHost(hostCore *abstract.HostCore, newHost *abstract.HostFull) (xerr fail.Error) {
	if hostCore == nil {
		return fail.InvalidParameterCannotBeNilError("hostCore")
	}
	if newHost == nil {
		return fail.InvalidParameterCannotBeNilError("newHost")
	}

	defer fail.OnPanic(&xerr)

	hostCore.ID = newHost.GetID()
	if hostCore.Name == "" {
		hostCore.Name = newHost.GetName()
	}

	return nil
}

func verifyVirtResizeCanAccessKernel() (xerr fail.Error) {
	command := "echo /boot/vmlinuz-`uname -r`"
	cmd := exec.Command("bash", "-c", command)

	cmdOutput := &bytes.Buffer{}
	cmd.Stdout = cmdOutput
	err := cmd.Run()
	if err != nil {
		return fail.NewError("command failed: '%s'\n%s", command, err.Error())
	}

	target := strings.TrimSpace(cmdOutput.String())
	_, err = os.Stat(target)
	if os.IsNotExist(err) {
		logrus.Warnf("Kernel file [%s] not found", target)
		return nil
	}

	return fail.Wrap(unix.Access(target, unix.R_OK), "")
}

// CreateHost creates an host satisfying request
func (s stack) CreateHost(request abstract.HostRequest) (host *abstract.HostFull, _ *abstract.HostTemplate, userData *userdata.Content, xerr fail.Error) {
	if s.IsNull() {
		return nil, nil, nil, fail.InvalidInstanceError()
	}

	defer fail.OnPanic(&xerr)

	resourceName := request.ResourceName
	hostName := request.HostName
	networks := request.Networks
	publicIP := request.PublicIP
	templateID := request.TemplateRef
	imageID := request.ImageRef
	keyPair := request.KeyPair

	userData = userdata.NewContent()

	// ----Check Inputs----
	if resourceName == "" {
		return nil, nil, nil, fail.InvalidParameterError("request.ResourceName", "cannit be empty string")
	}
	if hostName == "" {
		hostName = resourceName
	}
	if networks == nil || len(networks) == 0 {
		return nil, nil, userData, fail.InvalidParameterError("request.Networks", "cannot be nil or an empty slice")
	}

	if templateID == "" {
		return nil, nil, userData, fail.InvalidParameterError("request.templateID", "cannot be empty string")
	}
	if imageID == "" {
		return nil, nil, userData, fail.InvalidParameterError("request.ImageRef", "cannot be empty string")
	}
	hostC, _, xerr := s.getHostAndDomainFromRef(resourceName)
	host.Core = hostC

	if xerr == nil && host != nil {
		return nil, nil, userData, fail.DuplicateError("the host '%s' already exists", resourceName)
	}

	// ----Initialize----
	if keyPair == nil {
		var err error
		keyPair, err = s.CreateKeyPair(fmt.Sprintf("key_%s", resourceName))
		if err != nil {
			return nil, nil, userData, fail.Wrap(err, "keypair creation failed")
		}
		request.KeyPair = keyPair
	}
	if request.Password == "" {
		password, err := utils.GeneratePassword(16)
		if err != nil {
			return nil, nil, userData, fail.Wrap(err, "failed to generate password")
		}
		request.Password = password
	}

	template, xerr := s.InspectTemplate(templateID)
	if xerr != nil {
		return nil, nil, userData, fail.Wrap(xerr, "failed to get template infos")
	}
	imagePath, err := getImagePathFromID(s, imageID)
	if err != nil {
		return nil, nil, userData, fail.Wrap(err, "failed to get image path")
	}
	imageDisk, err := getDiskFromID(s, imageID)
	if err != nil {
		return nil, nil, userData, fail.Wrap(err, "failed to get disk from id")
	}

	err = userData.Prepare(*s.Config, request, networks[0].CIDR, defaultNetworkCIDR)
	if err != nil {
		return nil, nil, userData, fail.Wrap(err, "failed to prepare user data content")
	}

	// ----Commands----
	var vmInfoChannel chan VMInfo
	networksCommandString := ""
	for _, network := range networks {
		networksCommandString += fmt.Sprintf(" --network network=%s", network.Name)
	}

	if publicIP {
		command := ""
		if bridgedVMs {
			command = "ip route get 8.8.8.8 |awk -F\"src \" 'NR==1{split($2,a,\" \");print a[1]}'"
		} else {
			networkDefault, err := s.InspectNetwork("default")
			if err != nil {
				switch err.(type) {
				case *fail.ErrNotFound:
					networkDefault, err = s.CreateNetwork(
						abstract.NetworkRequest{
							Name:      "default",
							IPVersion: ipversion.IPv4,
							CIDR:      defaultNetworkCIDR,
						},
					)
					if err != nil {
						return nil, nil, userData, fail.Wrap(err, "failed to create network 'default'")
					}
				default:
					return nil, nil, userData, fail.Wrap(err, "failed to get network 'default'")
				}
			}

			command = "ip route | grep " + networkDefault.CIDR + " |awk -F\"src \" 'NR==1{split($2,a,\" \");print a[1]}'"
		}
		cmd := exec.Command("bash", "-c", command)
		cmdOutput := &bytes.Buffer{}
		cmd.Stdout = cmdOutput
		ferr := cmd.Run()
		if ferr != nil {
			return nil, nil, nil, fail.NewError("command failed: '%s'\n%s", command, err.Error())
		}
		ip := strings.Trim(fmt.Sprint(cmdOutput), "\n ")

		if bridgedVMs {
			infoWaiter, err := GetInfoWaiter()
			if err != nil {
				return nil, nil, userData, fail.Wrap(err, "failed to get info waiter")
			}

			userData.AddInTag(userdata.PHASE2_NETWORK_AND_SECURITY, "insert_tag", fmt.Sprintf(`
 LANIP=$(ip route get 8.8.8.8 | awk -F"src " 'NR==1{split($2,a," ");print a[1]}')
 echo -n "%s|$LANIP" > /dev/tcp/%s/%d`, hostName, ip, infoWaiter.port))

			command = "ip route get 8.8.8.8 | awk -F\"dev \" 'NR==1{split($2,a,\" \");print a[1]}'"
			cmd = exec.Command("bash", "-c", command)
			cmdOutput = &bytes.Buffer{}
			cmd.Stdout = cmdOutput
			ferr = cmd.Run()
			if ferr != nil {
				return nil, nil, userData, fail.Wrap(ferr, "command failed: '%s'\n", command)
			}
			lanIf := strings.Trim(fmt.Sprint(cmdOutput), "\n ")
			networksCommandString += fmt.Sprintf(" --network type=direct,source=%s,source_mode=bridge", lanIf)
			vmInfoChannel = infoWaiter.Register(hostName)
		} else {
			networksCommandString += fmt.Sprintf(" --network network=default")
		}

	}

	userDataPhase1, err := userData.Generate(userdata.PHASE1_INIT)
	if err != nil {
		return nil, nil, userData, err
	}
	userdataFileName := s.LibvirtConfig.LibvirtStorage + "/" + resourceName + "_userdata.sh"
	werr := ioutil.WriteFile(userdataFileName, userDataPhase1, 0644)
	if werr != nil {
		return nil, nil, userData, fail.Wrap(werr, "failed to write userData in %s_userdata.sh file", resourceName)
	}

	// without sudo rights /boot/vmlinuz/`uname -r` have to be readable by the user to execute virt-resize / virt-sysprep
	err = verifyVirtResizeCanAccessKernel()
	if err != nil {
		return nil, nil, userData, fail.NewError("libvirt cannot access /boot/vmlinuz/`uname -r`, this file must be readable in order to be used by libvirt")
	}

	var commands []string
	// TODO: gpu is ignored
	// TODO: use libvirt-go functions not bash commands
	commandSetup := fmt.Sprintf("IMAGE_PATH=\"%s\" && IMAGE=\"`echo $IMAGE_PATH | rev | cut -d/ -f1 | rev`\" && EXT=\"`echo $IMAGE | grep -o '[^.]*$'`\" && LIBVIRT_STORAGE=\"%s\" && HOST_NAME=\"%s\" && VM_IMAGE=\"$LIBVIRT_STORAGE/$HOST_NAME.$EXT\"", imagePath, s.LibvirtConfig.LibvirtStorage, resourceName)

	commandResize := fmt.Sprintf("cd $LIBVIRT_STORAGE && chmod 666 $IMAGE_PATH && truncate $VM_IMAGE -s %dG && virt-resize --expand %s $IMAGE_PATH $VM_IMAGE", template.DiskSize, imageDisk)
	commands = append(commands, commandResize)

	commandSysprep := fmt.Sprintf("virt-sysprep -a $VM_IMAGE --hostname %s --operations defaults,-ssh-hostkeys --firstboot %s && rm %s", hostName, userdataFileName, userdataFileName)
	commands = append(commands, commandSysprep)

	commandVirtInstall := fmt.Sprintf("virt-install --connect \"%s\" --noautoconsole --name=%s --vcpus=%d --memory=%d --import --disk=$VM_IMAGE %s", s.LibvirtConfig.URI, resourceName, template.Cores, int(template.RAMSize*1024), networksCommandString)
	commands = append(commands, commandVirtInstall)

	for _, command := range commands {
		joinCommand := strings.Join([]string{commandSetup, command}, " && ")

		cmd := exec.Command("bash", "-c", joinCommand)

		cmdOutput := &bytes.Buffer{}
		cmdError := &bytes.Buffer{}
		cmd.Stdout = cmdOutput
		cmd.Stderr = cmdError
		ferr := cmd.Run()
		if ferr != nil {
			logrus.Errorf("Commands failed: [%s] with error [%s], stdOutput [%s] and stdError [%s]", command, ferr.Error(), cmdOutput.String(), cmdError.String())
			return nil, nil, userData, fail.NewError("command failed: '%s'\n%s", command, ferr.Error())
		}
	}

	// starting from here delete host if failure
	defer func() {
		if err != nil {
			if derr := s.DeleteHost(resourceName); derr != nil {
				fmt.Printf("failed to Remove the host %s: %s", resourceName, err.Error())
			}
		}
	}()

	// ----Generate abstract.IPAddress----

	domain, werr := s.LibvirtService.LookupDomainByName(resourceName)
	if werr != nil {
		return nil, nil, userData, fail.Wrap(werr, "cannot find domain '%s'", resourceName)
	}

	hostCore, err := s.getHostFromDomain(domain)
	if err != nil {
		return nil, nil, userData, fail.Wrap(err, "failed to get host '%s' from domain", resourceName)
	}

	hostCore.PrivateKey = userData.FirstPrivateKey
	hostCore.Password = request.Password

	hostNetwork := abstract.NewHostSubnet()
	if bridgedVMs {
		var vmInfo VMInfo
		if publicIP {
			vmInfo = <-vmInfoChannel
			userData.PublicIP = vmInfo.publicIP
		}
	}

	hostNetwork.DefaultNetworkID = request.Networks[0].ID
	hostNetwork.IsGateway = request.IsGateway

	// FIXME: Get gateway info

	host = abstract.NewHostFull()
	host.Core = hostCore
	host.Networking = hostNetwork
	host.Sizing = converters.HostTemplateToHostEffectiveSizing(template)
	return host, userData, nil
}

// GetHost returns the host identified by ref (name or id) or by a *abstract.IPAddress containing an id
func (s stack) InspectHost(hostParam stacks.HostParameter) (host *abstract.HostFull, xerr fail.Error) {
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	ahc, _, err := stacks.ValidateHostParameter(hostParam)
	if err != nil {
		return ahc, err
	}

	newHost, _, err := s.getHostAndDomainFromRef(ahc.GetID())
	if err != nil {
		return nil, err
	}

	host = abstract.NewHostFull()

	if err = s.complementHost(newHost, host); err != nil {
		return nil, fail.Wrap(err, "failed to complement the host")
	}

	if !host.OK() {
		logrus.Tracef("Unexpected host status: %s", spew.Sdump(host))
	}

	return host, nil
}

// GetHostByName returns the host identified by ref (name or id)
func (s stack) GetHostByName(name string) (*abstract.HostCore, fail.Error) {
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	host, err := s.InspectHost(name)
	if err != nil {
		return nil, err
	}
	return host.Core, nil
}

// DeleteHost deletes the host identified by id
func (s stack) DeleteHost(hostParam stacks.HostParameter) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, _, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	_, domain, xerr := s.getHostAndDomainFromRef(ahf.GetID())
	if xerr != nil {
		return xerr
	}

	volumes, xerr := getVolumesFromDomain(domain, s.LibvirtService)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to get the volumes from the domain")
	}

	isActive, err := domain.IsActive()
	if err != nil {
		return fail.Wrap(err, "failed to know if the domain is active")
	}

	if !isActive {
		err := s.StartHost(ahf.Core.ID)
		if err != nil {
			return fail.Wrap(err, "failed to start the domain")
		}
	}

	if err = domain.Destroy(); err != nil {
		return fail.Wrap(err, "failed to destroy the domain")
	}

	if err = domain.Undefine(); err != nil {
		return fail.Wrap(err, "failed to undefine the domain")
	}

	for _, volume := range volumes {
		volumePath := volume.Key
		pathSplitted := strings.Split(volumePath, "/")
		volumeName := strings.Split(pathSplitted[len(pathSplitted)-1], ".")[0]
		domainName, err := domain.GetName()
		if err != nil {
			return fail.Wrap(err, "failed to get domain name")
		}

		if domainName == volumeName {
			if err = s.DeleteVolume(volume.Name); err != nil {
				return fail.Wrap(err, "failed to delete volume '%s'", volumeName)
			}
		}
	}

	return nil
}

// ResizeHost change the template used by an host
func (s stack) ResizeHost(hostParam stacks.HostParameter, request abstract.SizingRequirements) (*abstract.HostFull, fail.Error) {
	return nil, fail.NotImplementedError("ResizeHost() not implemented yet") // FIXME: Technical debt
}

// ListHosts lists available hosts
func (s stack) ListHosts() (hosts abstract.HostList, xerr fail.Error) {
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	domains, xerr := s.LibvirtService.ListAllDomains(16383)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "error listing domains")
	}

	for _, domain := range domains {
		hostC, xerr := s.getHostFromDomain(&domain)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to get host from domain")
		}

		host := abstract.NewHostFull()
		host.Core = hostC

		hosts = append(hosts, host)
	}

	return hosts, nil
}

// StopHost stops the host identified by id
func (s stack) StopHost(hostParam stacks.HostParameter, gracefully bool) fail.Error {
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	_, domain, xerr := s.getHostAndDomainFromRef(ahf.GetID())
	if xerr != nil {
		return fail.Wrap(xerr, "getHostAndDomainFromRef failed")
	}

	if err := domain.Shutdown(); err != nil {
		return fail.Wrap(err, "failed to shutdown the host '%s'", hostRef)
	}

	return nil
}

// StartHost starts the host identified by id
func (s stack) StartHost(hostParam stacks.HostParameter) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, hostLabel, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	_, domain, err := s.getHostAndDomainFromRef(ahf.Core.ID)
	if err != nil {
		return fail.Wrap(err, "getHostAndDomainFromRef")
	}

	if err := domain.Create(); err != nil {
		return fail.Wrap(err, "failed to launch the host %s", hostLabel)
	}

	return nil
}

// RebootHost reboot the host identified by id
func (s stack) RebootHost(hostParam stacks.HostParameter) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, hostLabel, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	_, domain, xerr := s.getHostAndDomainFromRef(ahf.Core.GetID())
	if xerr != nil {
		return fail.Wrap(xerr, "getHostAndDomainFromRef failed")
	}

	if err := domain.Reboot(0); err != nil {
		return fail.Wrap(err, "failed to reboot the host '%s'", hostLabel)
	}

	return nil
}

// GetHostState returns the host identified by id
func (s stack) GetHostState(hostParam stacks.HostParameter) (hoststate.Enum, fail.Error) {
	if s.IsNull() {
		return hoststate.UNKNOWN, fail.InvalidInstanceError()
	}

	host, xerr := s.InspectHost(hostParam)
	if xerr != nil {
		return hoststate.ERROR, xerr
	}

	return host.CurrentState, nil
}

// -------------Provider Infos-------------------------------------------------------------------------------------------

// ListAvailabilityZones lists the usable AvailabilityZones
func (s stack) ListAvailabilityZones() (map[string]bool, fail.Error) {
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	return map[string]bool{"local": true}, nil
}

func (s stack) ListRegions() ([]string, fail.Error) {
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	return []string{"local"}, nil
}

// BindSecurityGroupToHost ...
func (s stack) BindSecurityGroupToHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	return fail.NotImplementedError("not yet implemented")
}

// UnbindSecurityGroupFromHost ...
func (s stack) UnbindSecurityGroupFromHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	return fail.NotImplementedError("not yet implemented")
}

func (s Stack) InspectTemplate(id string) (*abstract.HostTemplate, fail.Error) {
	return &abstract.HostTemplate{}, nil
}
