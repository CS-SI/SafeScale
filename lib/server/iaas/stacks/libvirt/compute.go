// +build libvirt

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

	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/libvirt/libvirt-go"
	libvirtxml "github.com/libvirt/libvirt-go-xml"
	uuid "github.com/satori/go.uuid"

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/ipversion"
	propsv1 "github.com/CS-SI/SafeScale/lib/server/iaas/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
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
func (s *Stack) ListImages() (images []resources.Image, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	jsonFile, err := os.Open(s.LibvirtConfig.ImagesJSONPath)
	if err != nil {
		return nil, scerr.Errorf(
			fmt.Sprintf("failed to open %s : %s", s.LibvirtConfig.ImagesJSONPath, err.Error()), err,
		)
	}
	defer func() {
		if err := jsonFile.Close(); err != nil {
			fmt.Println("failed to close images file")
		}
	}()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, scerr.Errorf(
			fmt.Sprintf("failed to read %s : %s", s.LibvirtConfig.ImagesJSONPath, err.Error()), err,
		)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(byteValue), &result); err != nil {
		return nil, scerr.Errorf(
			fmt.Sprintf(
				"failed to unmarshal jsonFile %s : %s", s.LibvirtConfig.ImagesJSONPath, err.Error(),
			), err,
		)
	}

	imagesJSON := result["images"].([]interface{})
	images = []resources.Image{}
	for _, imageJSON := range imagesJSON {
		image := resources.Image{
			ID:   imageJSON.(map[string]interface{})["imageID"].(string),
			Name: imageJSON.(map[string]interface{})["imageName"].(string),
		}
		images = append(images, image)
	}

	return images, nil
}

// GetImage returns the Image referenced by id
func (s *Stack) GetImage(id string) (image *resources.Image, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if id == "" {
		return nil, scerr.InvalidParameterError("id", "cannot be empty string")
	}

	jsonFile, err := os.Open(s.LibvirtConfig.ImagesJSONPath)
	if err != nil {
		return nil, scerr.Errorf(
			fmt.Sprintf("failed to open %s : %s", s.LibvirtConfig.ImagesJSONPath, err.Error()), err,
		)
	}
	defer func() {
		if err := jsonFile.Close(); err != nil {
			fmt.Println("failed to close images file")
		}
	}()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, scerr.Errorf(
			fmt.Sprintf("failed to read %s : %s", s.LibvirtConfig.ImagesJSONPath, err.Error()), err,
		)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(byteValue), &result); err != nil {
		return nil, scerr.Errorf(
			fmt.Sprintf(
				"failed to unmarshal jsonFile %s : %s", s.LibvirtConfig.ImagesJSONPath, err.Error(),
			), err,
		)
	}

	imagesJSON := result["images"].([]interface{})
	for _, imageJSON := range imagesJSON {
		if imageID, ok := imageJSON.(map[string]interface{})["imageID"]; ok && imageID == id {
			return &resources.Image{
				ID:   imageJSON.(map[string]interface{})["imageID"].(string),
				Name: imageJSON.(map[string]interface{})["imageName"].(string),
			}, nil
		}
		if imageName, ok := imageJSON.(map[string]interface{})["imageName"]; ok && imageName == id {
			return &resources.Image{
				ID:   imageJSON.(map[string]interface{})["imageID"].(string),
				Name: imageJSON.(map[string]interface{})["imageName"].(string),
			}, nil
		}
	}

	return nil, scerr.Errorf(fmt.Sprintf("image with id=%s not found", id), err)
}

// -------------TEMPLATES------------------------------------------------------------------------------------------------

// ListTemplates overload OpenStack ListTemplate method to filter wind and flex instance and add GPU configuration
func (s *Stack) ListTemplates() (templates []resources.HostTemplate, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	jsonFile, err := os.Open(s.LibvirtConfig.TemplatesJSONPath)
	if err != nil {
		return nil, scerr.Errorf(
			fmt.Sprintf("failed to open %s : %s", s.LibvirtConfig.TemplatesJSONPath, err.Error()), err,
		)
	}
	defer func() {
		if err := jsonFile.Close(); err != nil {
			fmt.Println("failed to close template file")
		}
	}()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, scerr.Errorf(
			fmt.Sprintf("failed to read %s : %s", s.LibvirtConfig.TemplatesJSONPath, err.Error()), err,
		)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(byteValue), &result); err != nil {
		return nil, scerr.Errorf(
			fmt.Sprintf(
				"failed to unmarshal jsonFile %s : %s", s.LibvirtConfig.TemplatesJSONPath, err.Error(),
			), err,
		)
	}

	templatesJSON := result["templates"].([]interface{})
	templates = []resources.HostTemplate{}
	for _, templateJSON := range templatesJSON {
		template := resources.HostTemplate{
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
func (s *Stack) GetTemplate(id string) (template *resources.HostTemplate, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	jsonFile, err := os.Open(s.LibvirtConfig.TemplatesJSONPath)
	if err != nil {
		return nil, scerr.Errorf(
			fmt.Sprintf("failed to open %s : %s", s.LibvirtConfig.TemplatesJSONPath, err.Error()), err,
		)
	}
	defer func() {
		if err := jsonFile.Close(); err != nil {
			fmt.Println("failed to close template file")
		}
	}()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, scerr.Errorf(
			fmt.Sprintf("failed to read %s : %s", s.LibvirtConfig.TemplatesJSONPath, err.Error()), err,
		)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(byteValue), &result); err != nil {
		return nil, scerr.Errorf(
			fmt.Sprintf(
				"failed to unmarshal jsonFile %s : %s", s.LibvirtConfig.TemplatesJSONPath, err.Error(),
			), err,
		)
	}

	templatesJSON := result["templates"].([]interface{})
	for _, templateJSON := range templatesJSON {
		if templateID, _ := templateJSON.(map[string]interface{})["templateID"]; templateID == id {
			return &resources.HostTemplate{
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

	return nil, scerr.Errorf(fmt.Sprintf("template with id=%s not found", id), err)
}

// -------------SSH KEYS-------------------------------------------------------------------------------------------------

// CreateKeyPair creates a key pair (no import)
func (s *Stack) CreateKeyPair(name string) (*resources.KeyPair, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	// privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	// publicKey := privateKey.PublicKey
	// pub, _ := ssh.NewPublicKey(&publicKey)
	// pubBytes := ssh.MarshalAuthorizedKey(pub)
	// pubKey := string(pubBytes)

	// priBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	// priKeyPem := pem.EncodeToMemory(
	// 	&pem.Block{
	// 		Type:  "RSA PRIVATE KEY",
	// 		Bytes: priBytes,
	// 	},
	// )

	// priKey := string(priKeyPem)

	kp, err := resources.NewKeyPair(name)
	if err != nil {
		return nil, err
	}
	kp.ID, err = uuid.NewV4()
	if err != nil {
		return nil, scerr.Errorf(fmt.Sprintf("failed to generate uuid key : %s", err.Error()), err)
	}
	return kp, nil
}

// GetKeyPair returns the key pair identified by id
func (s *Stack) GetKeyPair(id string) (*resources.KeyPair, error) {
	return nil, scerr.NotImplementedError("GetKeyPair() not implemented yet") // FIXME: Technical debt
}

// ListKeyPairs lists available key pairs
func (s *Stack) ListKeyPairs() ([]resources.KeyPair, error) {
	return nil, scerr.NotImplementedError("ListKeyPairs() not implemented yet") // FIXME: Technical debt
}

// DeleteKeyPair deletes the key pair identified by id
func (s *Stack) DeleteKeyPair(id string) error {
	return scerr.NotImplementedError("DeleteKeyPair() not implemented yet") // FIXME: Technical debt
}

// -------------HOST MANAGEMENT------------------------------------------------------------------------------------------
func downloadImage(path string, downloadInfo map[string]interface{}) error {
	switch downloadInfo["method"].(string) {
	case "GoogleDrive":
		command := fmt.Sprintf(
			`file_name="%s"
 file_id="%s"
 cookie_file="%s/cookie.txt"
 query=$(curl -c ${cookie_file} -s -L "https://drive.google.com/uc?export=download&id=${file_id}" | perl -nE'say/uc-download-link.*? href="(.*?)\">/' | sed -e 's/amp;//g' | sed -n 2p)
 url="https://drive.google.com$query"
 curl -b ${cookie_file} -L -o ${file_name} $url
 rm ${cookie_file}`, path, downloadInfo["id"].(string), filepath.Dir(path),
		)
		cmd := exec.Command("bash", "-c", command)
		err := cmd.Run()
		if err != nil {
			return scerr.Errorf(fmt.Sprintf("Commands failed : \n%s\n%s", command, err.Error()), err)
		}
	default:
		return scerr.NotImplementedError(
			fmt.Sprintf(
				"download method %s not implemented", downloadInfo["method"].(string),
			),
		)
	}
	return nil
}

// getImagePathFromID retrieve the storage path of an image from this image ID
func getImagePathFromID(s *Stack, id string) (path string, err error) {
	jsonFile, err := os.Open(s.LibvirtConfig.ImagesJSONPath)
	if err != nil {
		return "", scerr.Errorf(fmt.Sprintf("failed to open %s : %s", s.LibvirtConfig.ImagesJSONPath, err.Error()), err)
	}
	defer func() {
		if err := jsonFile.Close(); err != nil {
			fmt.Println("failed to close image file")
		}
	}()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return "", scerr.Errorf(fmt.Sprintf("failed to read %s : %s", s.LibvirtConfig.ImagesJSONPath, err.Error()), err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(byteValue), &result); err != nil {
		return "", scerr.Errorf(
			fmt.Sprintf(
				"failed to unmarshal jsonFile %s : %s", s.LibvirtConfig.ImagesJSONPath, err.Error(),
			), err,
		)
	}

	imagesJSON := result["images"].([]interface{})
	for _, imageJSON := range imagesJSON {
		if imageID, _ := imageJSON.(map[string]interface{})["imageID"]; imageID == id {
			path := imageJSON.(map[string]interface{})["imagePath"].(string)
			// check parent directory first
			parentDir := filepath.Dir(path)
			if _, err := os.Stat(parentDir); os.IsNotExist(err) {
				if err != nil {
					return "", scerr.Errorf(
						fmt.Sprintf(
							"failed to download image : directory %s doesn't exist", parentDir,
						), err,
					)
				}
			}
			// download if image file isn't there
			if _, err := os.Stat(path); os.IsNotExist(err) {
				err := downloadImage(path, imageJSON.(map[string]interface{})["download"].(map[string]interface{}))
				if err != nil {
					return "", scerr.Errorf(fmt.Sprintf("failed to download image : %s", err.Error()), err)
				}
			} else if err != nil {
				return "", scerr.Errorf(
					fmt.Sprintf(
						"unable to check if the file %s exists or not : %s", filepath.Base(path), err.Error(),
					), err,
				)
			}
			return path, nil
		}
	}

	return "", scerr.Errorf(fmt.Sprintf("image with id=%s not found", id), err)
}

// getDiskFromID retrieve the disk with root partition of an image from this image ID
func getDiskFromID(s *Stack, id string) (disk string, err error) {
	jsonFile, err := os.Open(s.LibvirtConfig.ImagesJSONPath)
	if err != nil {
		return "", scerr.Errorf(fmt.Sprintf("failed to open %s : %s", s.LibvirtConfig.ImagesJSONPath, err.Error()), err)
	}
	defer func() {
		if err := jsonFile.Close(); err != nil {
			fmt.Println("failed to close image file")
		}
	}()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return "", scerr.Errorf(fmt.Sprintf("failed to read %s : %s", s.LibvirtConfig.ImagesJSONPath, err.Error()), err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(byteValue), &result); err != nil {
		return "", scerr.Errorf(
			fmt.Sprintf(
				"failed to unmarshal jsonFile %s : %s", s.LibvirtConfig.ImagesJSONPath, err.Error(),
			), err,
		)
	}

	imagesJSON := result["images"].([]interface{})
	for _, imageJSON := range imagesJSON {
		if imageID, _ := imageJSON.(map[string]interface{})["imageID"]; imageID == id {
			return imageJSON.(map[string]interface{})["disk"].(string), nil
		}
	}

	return "", scerr.Errorf(fmt.Sprintf("image with id=%s not found", id), err)
}

func getVolumesFromDomain(domain *libvirt.Domain, libvirtService *libvirt.Connect) ([]*libvirtxml.StorageVolume, error) {
	var volumeDescriptions []*libvirtxml.StorageVolume
	var domainVolumePaths []string

	// List paths of domain disks
	domainXML, err := domain.GetXMLDesc(0)
	if err != nil {
		return nil, scerr.Errorf(
			fmt.Sprintf(fmt.Sprintf("failed get xml description of a domain : %s", err.Error())), err,
		)
	}
	domainDescription := &libvirtxml.Domain{}
	err = xml.Unmarshal([]byte(domainXML), domainDescription)
	if err != nil {
		return nil, scerr.Errorf(
			fmt.Sprintf(fmt.Sprintf("failed unmarshall the domain description : %s", err.Error())), err,
		)
	}
	domainDisks := domainDescription.Devices.Disks

	for _, disk := range domainDisks {
		domainVolumePaths = append(domainVolumePaths, disk.Source.File.File)
	}

	// Check which volumes match these paths
	pools, err := libvirtService.ListAllStoragePools(2)
	if err != nil {
		return nil, scerr.Errorf(fmt.Sprintf(fmt.Sprintf("failed list pools : %s", err.Error())), err)
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
				return nil, scerr.Errorf(
					fmt.Sprintf(
						fmt.Sprintf(
							"failed unmarshall the volume description : %s", err.Error(),
						),
					), err,
				)
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

// stateConvert convert libvirt.DomainState to a hoststate.Enum
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

func getDescriptionV1FromDomain(domain *libvirt.Domain, libvirtService *libvirt.Connect) (*propsv1.HostDescription, error) {
	hostDescription := propsv1.NewHostDescription()

	// var Created time.Time
	// var Creator string
	// var Updated time.Time
	// var Purpose string

	// There is a creation and modification timestamp on disks but it'not the best way to get the vm creation / modification date

	return hostDescription, nil
}
func getSizingV1FromDomain(domain *libvirt.Domain, libvirtService *libvirt.Connect) (*propsv1.HostSizing, error) {
	hostSizing := propsv1.NewHostSizing()

	info, err := domain.GetInfo()
	if err != nil {
		return nil, scerr.Errorf(fmt.Sprintf(fmt.Sprintf("failed to get infos from the domain : %s", err.Error())), err)
	}

	diskSize := 0
	volumes, err := getVolumesFromDomain(domain, libvirtService)
	if err != nil {
		return nil, scerr.Errorf(
			fmt.Sprintf(fmt.Sprintf("failed to get volumes from the domain : %s", err.Error())), err,
		)
	}
	for _, volume := range volumes {
		diskSize += int(volume.Capacity.Value / 1024 / 1024 / 1024)
	}

	hostSizing.AllocatedSize.RAMSize = float32(info.MaxMem) / 1024 / 1024
	hostSizing.AllocatedSize.Cores = int(info.NrVirtCpu)
	hostSizing.AllocatedSize.DiskSize = diskSize
	// TODO GPU not implemented
	hostSizing.AllocatedSize.GPUNumber = 0
	hostSizing.AllocatedSize.GPUType = ""

	// hostSizing.RequestedSize and hostSizing.Template are unknown by libvirt and are left unset

	return hostSizing, nil
}
func (s *Stack) getNetworkV1FromDomain(domain *libvirt.Domain) (*propsv1.HostNetwork, error) {
	hostNetwork := propsv1.NewHostNetwork()

	domainXML, err := domain.GetXMLDesc(0)
	if err != nil {
		return nil, scerr.Errorf(
			fmt.Sprintf(fmt.Sprintf("failed get xml description of a domain : %s", err.Error())), err,
		)
	}
	domainDescription := &libvirtxml.Domain{}
	err = xml.Unmarshal([]byte(domainXML), domainDescription)

	networks, err := s.LibvirtService.ListAllNetworks(3)
	if err != nil {
		return nil, scerr.Errorf(fmt.Sprintf("failed to list all networks : %s", err.Error()), err)
	}

	for _, iface := range domainDescription.Devices.Interfaces {
		if iface.Source.Network != nil {
			err = retry.WhileUnsuccessfulDelay5Seconds(
				func() error {
					for _, network := range networks {
						name, err := network.GetName()
						if err != nil {
							return scerr.Errorf(fmt.Sprintf("failed to get network name : %s", err.Error()), err)
						}
						if name == iface.Source.Network.Network {
							dhcpLeases, err := network.GetDHCPLeases()
							if err != nil {
								return scerr.Errorf(
									fmt.Sprintf("failed to get network dhcpLeases : %s", err.Error()), err,
								)
							}
							for _, dhcpLease := range dhcpLeases {
								if dhcpLease.Mac == iface.MAC.Address {
									net, err := s.GetNetwork(iface.Source.Network.Network)
									if err != nil {
										return scerr.Errorf(
											fmt.Sprintf(
												"unknown Network %s", iface.Source.Network.Network,
											), err,
										)
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
										return scerr.Errorf(fmt.Sprintf("unknown adressType"), err)
									}
									hostNetwork.NetworksByID[net.ID] = net.Name
									hostNetwork.NetworksByName[net.Name] = net.ID
									return nil
								}
							}
						}
					}
					return scerr.Errorf(fmt.Sprintf("no local IP matching inteface %s found", iface.Alias), err)
				},
				temporal.GetHostTimeout(),
			)

		}
	}
	return hostNetwork, nil
}

// getHostFromDomain build a resources.Host struct representing a Domain
func (s *Stack) getHostFromDomain(domain *libvirt.Domain) (*resources.Host, error) {
	id, err := domain.GetUUIDString()
	if err != nil {
		return nil, scerr.Errorf(fmt.Sprintf(fmt.Sprintf("failed to fetch id from domain : %s", err.Error())), err)
	}
	name, err := domain.GetName()
	if err != nil {
		return nil, scerr.Errorf(fmt.Sprintf(fmt.Sprintf("failed to fetch name from domain : %s", err.Error())), err)
	}
	state, _, err := domain.GetState()
	if err != nil {
		return nil, scerr.Errorf(fmt.Sprintf(fmt.Sprintf("failed to fetch state from domain : %s", err.Error())), err)
	}

	host := resources.NewHost()

	host.ID = id
	host.Name = name
	host.PrivateKey = "Impossible to fetch them from the domain, the private key is unknown by the domain"
	host.LastState = stateConvert(state)

	err = host.Properties.LockForWrite(hostproperty.DescriptionV1).ThenUse(
		func(v interface{}) error {
			hostDescriptionV1, err := getDescriptionV1FromDomain(domain, s.LibvirtService)
			if err != nil {
				return scerr.Errorf(fmt.Sprintf(fmt.Sprintf("failed to get domain description : %s", err.Error())), err)
			}
			v.(*propsv1.HostDescription).Replace(hostDescriptionV1)
			return nil
		},
	)
	if err != nil {
		return nil, scerr.Errorf(fmt.Sprintf("failed to update hostproperty.DescriptionV1 : %s", err.Error()), err)
	}

	err = host.Properties.LockForWrite(hostproperty.SizingV1).ThenUse(
		func(v interface{}) error {
			hostSizingV1, err := getSizingV1FromDomain(domain, s.LibvirtService)
			if err != nil {
				return scerr.Errorf(fmt.Sprintf(fmt.Sprintf("failed to get domain sizing : %s", err.Error())), err)
			}
			v.(*propsv1.HostSizing).Replace(hostSizingV1)
			return nil
		},
	)
	if err != nil {
		return nil, scerr.Errorf(fmt.Sprintf("failed to update hostproperty.SizingV1 : %s", err.Error()), err)
	}

	err = host.Properties.LockForWrite(hostproperty.NetworkV1).ThenUse(
		func(v interface{}) error {
			hostNetworkV1, err := s.getNetworkV1FromDomain(domain)
			if err != nil {
				return scerr.Errorf(fmt.Sprintf(fmt.Sprintf("failed to get domain network : %s", err.Error())), err)
			}
			v.(*propsv1.HostNetwork).Replace(hostNetworkV1)
			return nil
		},
	)
	if err != nil {
		return nil, scerr.Errorf(fmt.Sprintf("failed to update hostproperty.NetworkV1 : %s", err.Error()), err)
	}

	return host, nil
}

// getHostAndDomainFromRef retrieve the host and the domain associated to an ref (id or name)
func (s *Stack) getHostAndDomainFromRef(ref string) (*resources.Host, *libvirt.Domain, error) {
	domain, err := s.LibvirtService.LookupDomainByUUIDString(ref)
	if err != nil {
		domain, err = s.LibvirtService.LookupDomainByName(ref)
		if err != nil {
			re, err2 := regexp.Compile("[0-9]+")
			if err2 != nil {
				return nil, nil, scerr.Errorf(
					fmt.Sprintf(
						fmt.Sprintf(
							"failed to fetch domain from ref : %s", err.Error(),
						),
					), err,
				)
			}
			errCode, _ := strconv.Atoi(re.FindString(err.Error()))
			if errCode == 42 {
				return nil, nil, resources.ResourceNotFoundError("host", ref)
			}
			return nil, nil, scerr.Errorf(
				fmt.Sprintf(fmt.Sprintf("failed to fetch domain from ref : %s", err.Error())), err,
			)
		}
	}
	host, err := s.getHostFromDomain(domain)
	if err != nil {
		return nil, nil, scerr.Errorf(fmt.Sprintf("failed to get host from domain : %s", err.Error()), err)
	}

	return host, domain, nil
}

func (s *Stack) complementHost(host *resources.Host, newHost *resources.Host) error {
	if host == nil || newHost == nil {
		return scerr.Errorf(fmt.Sprintf("both host and newHost have to be set"), err)
	}

	host.ID = newHost.ID
	if host.Name == "" {
		host.Name = newHost.Name
	}
	host.LastState = newHost.LastState

	err := host.Properties.LockForWrite(hostproperty.NetworkV1).ThenUse(
		func(v interface{}) error {
			newHostNetworkV1 := propsv1.NewHostNetwork()
			readlockErr := newHost.Properties.LockForRead(hostproperty.NetworkV1).ThenUse(
				func(v interface{}) error {
					newHostNetworkV1 = v.(*propsv1.HostNetwork)
					return nil
				},
			)
			if readlockErr != nil {
				return readlockErr
			}
			hostNetworkV1 := v.(*propsv1.HostNetwork)
			hostNetworkV1.IPv4Addresses = newHostNetworkV1.IPv4Addresses
			hostNetworkV1.IPv6Addresses = newHostNetworkV1.IPv6Addresses
			hostNetworkV1.NetworksByID = newHostNetworkV1.NetworksByID
			hostNetworkV1.NetworksByName = newHostNetworkV1.NetworksByName
			return nil
		},
	)
	if err != nil {
		return scerr.Errorf(fmt.Sprintf("failed to update hostproperty.NetworkV1 : %s", err.Error()), err)
	}

	err = host.Properties.LockForWrite(hostproperty.SizingV1).ThenUse(
		func(v interface{}) error {
			newHostSizingV1 := propsv1.NewHostSizing()
			readLockErr := newHost.Properties.LockForRead(hostproperty.SizingV1).ThenUse(
				func(v interface{}) error {
					newHostSizingV1 = v.(*propsv1.HostSizing)
					return nil
				},
			)
			if readLockErr != nil {
				return readLockErr
			}
			hostSizingV1 := v.(*propsv1.HostSizing)
			hostSizingV1.AllocatedSize.Cores = newHostSizingV1.AllocatedSize.Cores
			hostSizingV1.AllocatedSize.RAMSize = newHostSizingV1.AllocatedSize.RAMSize
			hostSizingV1.AllocatedSize.DiskSize = newHostSizingV1.AllocatedSize.DiskSize
			return nil
		},
	)
	if err != nil {
		return scerr.Errorf(fmt.Sprintf("failed to update hostproperty.SizingV1 : %s", err.Error()), err)
	}

	return nil
}

func verifyVirtResizeCanAccessKernel() (err error) {
	command := "echo /boot/vmlinuz-`uname -r`"
	cmd := exec.Command("bash", "-c", command)

	cmdOutput := &bytes.Buffer{}
	cmd.Stdout = cmdOutput
	err = cmd.Run()
	if err != nil {
		return scerr.Errorf(fmt.Sprintf("Commands failed : \n%s\n%s", command, err.Error()), err)
	}

	target := strings.TrimSpace(cmdOutput.String())
	_, err = os.Stat(target)
	if os.IsNotExist(err) {
		logrus.Warnf("Kernel file [%s] not found", target)
		return nil
	}

	return unix.Access(target, unix.R_OK)
}

// CreateHost creates an host satisfying request
func (s *Stack) CreateHost(request resources.HostRequest) (host *resources.Host, userData *userdata.Content, err error) {
	if s == nil {
		return nil, nil, scerr.InvalidInstanceError()
	}
	if request.KeyPair == nil {
		return nil, nil, scerr.InvalidParameterError("request.KeyPair", "cannot be nil")
	}

	resourceName := request.ResourceName
	hostName := request.HostName
	networks := request.Networks
	publicIP := request.PublicIP
	templateID := request.TemplateID
	imageID := request.ImageID
	keyPair := request.KeyPair
	defaultGateway := request.DefaultGateway

	userData = userdata.NewContent()

	// ----Check Inputs----
	if resourceName == "" {
		return nil, nil, scerr.Errorf(fmt.Sprintf("The ResourceName is mandatory "), err)
	}
	if hostName == "" {
		hostName = resourceName
	}
	if networks == nil || len(networks) == 0 {
		return nil, userData, scerr.Errorf(
			fmt.Sprintf(
				"the host %s must be on at least one network (even if public)", resourceName,
			), err,
		)
	}
	if defaultGateway == nil && !publicIP {
		return nil, userData, scerr.Errorf(
			fmt.Sprintf("the host %s must have a gateway or be public", resourceName), err,
		)
	}
	if templateID == "" {
		return nil, userData, scerr.Errorf(fmt.Sprintf("the TemplateID is mandatory"), err)
	}
	if imageID == "" {
		return nil, userData, scerr.Errorf(fmt.Sprintf("the ImageID is mandatory"), err)
	}
	host, _, err = s.getHostAndDomainFromRef(resourceName)
	if err == nil && host != nil {
		return nil, userData, scerr.Errorf(fmt.Sprintf("the Host %s already exists", resourceName), err)
	}

	// ----Initialize----
	if request.Password == "" {
		password, err := utils.GeneratePassword(16)
		if err != nil {
			return nil, userData, scerr.Errorf(fmt.Sprintf("failed to generate password: %s", err.Error()), err)
		}
		request.Password = password
	}

	template, err := s.GetTemplate(templateID)
	if err != nil {
		return nil, userData, scerr.Errorf(fmt.Sprintf("GetTemplate failed : %s", err.Error()), err)
	}
	imagePath, err := getImagePathFromID(s, imageID)
	if err != nil {
		return nil, userData, scerr.Errorf(fmt.Sprintf("GetImagePathFromID failled %s: ", err.Error()), err)
	}
	imageDisk, err := getDiskFromID(s, imageID)
	if err != nil {
		return nil, userData, scerr.Errorf(fmt.Sprintf("GetDiskFromID failled %s: ", err.Error()), err)
	}

	err = userData.Prepare(*s.Config, request, networks[0].CIDR, defaultNetworkCIDR)
	if err != nil {
		return nil, userData, scerr.Errorf(fmt.Sprintf("failed to prepare user data content: %+v", err), err)
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
			networkDefault, err := s.GetNetwork("default")
			if err != nil {
				switch err.(type) {
				case scerr.ErrNotFound:
					networkDefault, err = s.CreateNetwork(
						resources.NetworkRequest{
							Name:      "default",
							IPVersion: ipversion.IPv4,
							CIDR:      defaultNetworkCIDR,
						},
					)
					if err != nil {
						return nil, userData, scerr.Errorf(
							fmt.Sprintf(
								"failure To create network default : %s ", err.Error(),
							), err,
						)
					}
				default:
					return nil, userData, scerr.Errorf(
						fmt.Sprintf("failure To get network default : %s ", err.Error()), err,
					)
				}
			}

			command = "ip route | grep " + networkDefault.CIDR + " |awk -F\"src \" 'NR==1{split($2,a,\" \");print a[1]}'"
		}
		cmd := exec.Command("bash", "-c", command)
		cmdOutput := &bytes.Buffer{}
		cmd.Stdout = cmdOutput
		err = cmd.Run()
		if err != nil {
			return nil, nil, scerr.Errorf(fmt.Sprintf("Commands failed : \n%s\n%s", command, err.Error()), err)
		}
		ip := strings.Trim(fmt.Sprint(cmdOutput), "\n ")

		if bridgedVMs {
			infoWaiter, err := GetInfoWaiter()
			if err != nil {
				return nil, userData, scerr.Errorf(fmt.Sprintf("failed to get info waiter : %s", err.Error()), err)
			}

			userData.AddInTag(
				"phase2", "insert_tag", fmt.Sprintf(
					`
 LANIP=$(ip route get 8.8.8.8 | awk -F"src " 'NR==1{split($2,a," ");print a[1]}')
 echo -n "%s|$LANIP" > /dev/tcp/%s/%d`, hostName, ip, infoWaiter.port,
				),
			)

			command = "ip route get 8.8.8.8 | awk -F\"dev \" 'NR==1{split($2,a,\" \");print a[1]}'"
			cmd = exec.Command("bash", "-c", command)
			cmdOutput = &bytes.Buffer{}
			cmd.Stdout = cmdOutput
			err = cmd.Run()
			if err != nil {
				return nil, userData, scerr.Errorf(fmt.Sprintf("Commands failed : \n%s\n%s", command, err.Error()), err)
			}
			lanIf := strings.Trim(fmt.Sprint(cmdOutput), "\n ")
			networksCommandString += fmt.Sprintf(" --network type=direct,source=%s,source_mode=bridge", lanIf)
			vmInfoChannel = infoWaiter.Register(hostName)
		} else {
			networksCommandString += fmt.Sprintf(" --network network=default")
		}

	}

	userDataPhase1, err := userData.Generate("phase1")
	if err != nil {
		return nil, userData, err
	}
	userdataFileName := s.LibvirtConfig.LibvirtStorage + "/" + resourceName + "_userdata.sh"
	err = ioutil.WriteFile(userdataFileName, userDataPhase1, 0644)
	if err != nil {
		return nil, userData, scerr.Errorf(
			fmt.Sprintf(
				"failed to write userData in %s_userdata.sh file : %s", resourceName, err.Error(),
			), err,
		)
	}

	// without sudo rights /boot/vmlinuz/`uname -r` have to be readable by the user to execute virt-resize / virt-sysprep
	err = verifyVirtResizeCanAccessKernel()
	if err != nil {
		return nil, userData, scerr.Errorf(
			fmt.Sprintf("libvirt cannot access /boot/vmlinuz/`uname -r`, this file must be readable in order to be used by libvirt"),
			err,
		)
	}

	var commands []string
	// TODO gpu is ignored
	// TODO use libvirt-go functions not bash commands
	commandSetup := fmt.Sprintf(
		"IMAGE_PATH=\"%s\" && IMAGE=\"`echo $IMAGE_PATH | rev | cut -d/ -f1 | rev`\" && EXT=\"`echo $IMAGE | grep -o '[^.]*$'`\" && LIBVIRT_STORAGE=\"%s\" && HOST_NAME=\"%s\" && VM_IMAGE=\"$LIBVIRT_STORAGE/$HOST_NAME.$EXT\"",
		imagePath, s.LibvirtConfig.LibvirtStorage, resourceName,
	)

	commandResize := fmt.Sprintf(
		"cd $LIBVIRT_STORAGE && chmod 666 $IMAGE_PATH && truncate $VM_IMAGE -s %dG && virt-resize --expand %s $IMAGE_PATH $VM_IMAGE",
		template.DiskSize, imageDisk,
	)
	commands = append(commands, commandResize)

	commandSysprep := fmt.Sprintf(
		"virt-sysprep -a $VM_IMAGE --hostname %s --operations defaults,-ssh-hostkeys --firstboot %s && rm %s", hostName,
		userdataFileName, userdataFileName,
	)
	commands = append(commands, commandSysprep)

	commandVirtInstall := fmt.Sprintf(
		"virt-install --connect \"%s\" --noautoconsole --name=%s --vcpus=%d --memory=%d --import --disk=$VM_IMAGE %s",
		s.LibvirtConfig.URI, resourceName, template.Cores, int(template.RAMSize*1024), networksCommandString,
	)
	commands = append(commands, commandVirtInstall)

	for _, command := range commands {
		joinCommand := strings.Join([]string{commandSetup, command}, " && ")

		cmd := exec.Command("bash", "-c", joinCommand)

		cmdOutput := &bytes.Buffer{}
		cmdError := &bytes.Buffer{}
		cmd.Stdout = cmdOutput
		cmd.Stderr = cmdError
		err = cmd.Run()
		if err != nil {
			logrus.Errorf(
				"Commands failed: [%s] with error [%s], stdOutput [%s] and stdError [%s]", command, err.Error(),
				cmdOutput.String(), cmdError.String(),
			)
			return nil, userData, scerr.Errorf(fmt.Sprintf("Commands failed : \n%s\n%s", command, err.Error()), err)
		}
	}

	// starting from here delete host if failure
	defer func() {
		if err != nil {
			if derr := s.DeleteHost(resourceName); derr != nil {
				fmt.Printf("failed to Delete the host %s : %s", resourceName, err.Error())
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	// ----Generate resources.Host----

	domain, err := s.LibvirtService.LookupDomainByName(resourceName)
	if err != nil {
		return nil, userData, scerr.Errorf(
			fmt.Sprintf(
				fmt.Sprintf(
					"Can't find domain %s : %s", resourceName, err.Error(),
				),
			), err,
		)
	}

	host, err = s.getHostFromDomain(domain)
	if err != nil {
		return nil, userData, scerr.Errorf(
			fmt.Sprintf(
				fmt.Sprintf(
					"failed to get host %s from domain : %s", resourceName, err.Error(),
				),
			), err,
		)
	}

	host.PrivateKey = keyPair.PrivateKey
	host.Password = request.Password

	err = host.Properties.LockForWrite(hostproperty.NetworkV1).ThenUse(
		func(v interface{}) error {
			hostNetworkV1 := v.(*propsv1.HostNetwork)

			if bridgedVMs {
				var vmInfo VMInfo
				if publicIP {
					vmInfo = <-vmInfoChannel
					hostNetworkV1.PublicIPv4 = vmInfo.publicIP
					userData.PublicIP = vmInfo.publicIP
				}
			}

			hostNetworkV1.DefaultNetworkID = request.Networks[0].ID
			hostNetworkV1.IsGateway = request.DefaultGateway == nil && request.Networks[0].Name != resources.SingleHostNetworkName
			if request.DefaultGateway != nil {
				hostNetworkV1.DefaultGatewayID = request.DefaultGateway.ID

				gateway, err := s.InspectHost(request.DefaultGateway)
				if err != nil {
					return scerr.Errorf(fmt.Sprintf("failed to get gateway host : %s", err.Error()), err)
				}

				hostNetworkV1.DefaultGatewayPrivateIP = gateway.GetPrivateIP()
			}

			return nil
		},
	)
	if err != nil {
		return nil, userData, scerr.Errorf(
			fmt.Sprintf("failed to update hostproperty.NetworkV1 : %s", err.Error()), err,
		)
	}

	err = host.Properties.LockForWrite(hostproperty.SizingV1).ThenUse(
		func(v interface{}) error {
			hostSizingV1 := v.(*propsv1.HostSizing)

			hostSizingV1.RequestedSize.RAMSize = float32(template.RAMSize * 1024)
			hostSizingV1.RequestedSize.Cores = template.Cores
			hostSizingV1.RequestedSize.DiskSize = template.DiskSize
			// TODO GPU not implemented
			hostSizingV1.RequestedSize.GPUNumber = template.GPUNumber
			hostSizingV1.RequestedSize.GPUType = template.GPUType

			return nil
		},
	)
	if err != nil {
		return nil, userData, scerr.Errorf(fmt.Sprintf("failed to update hostproperty.SizingV1 : %s", err.Error()), err)
	}

	return host, userData, nil
}

// GetHost returns the host identified by ref (name or id) or by a *resources.Host containing an id
func (s *Stack) InspectHost(hostParam interface{}) (host *resources.Host, err error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	switch hostParam := hostParam.(type) {
	case string:
		if hostParam == "" {
			return nil, scerr.InvalidParameterError("hostParam", "cannot be an empty string")
		}
		host = resources.NewHost()
		host.ID = hostParam
	case *resources.Host:
		if hostParam == nil {
			return nil, scerr.InvalidParameterError("hostParam", "cannot be nil")
		}
		host = hostParam
	default:
		return nil, scerr.InvalidParameterError("hostParam", "must be a string or a *resources.Host")
	}

	newHost, _, err := s.getHostAndDomainFromRef(host.ID)
	if err != nil {
		return nil, err
	}

	if err = s.complementHost(host, newHost); err != nil {
		return nil, scerr.Errorf(fmt.Sprintf("failed to complement the host : %s", err.Error()), err)
	}

	if !host.OK() {
		logrus.Warnf("[TRACE] Unexpected host status: %s", spew.Sdump(host))
	}

	return host, nil
}

// GetHostByName returns the host identified by ref (name or id)
func (s *Stack) GetHostByName(name string) (*resources.Host, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	return s.InspectHost(name)
}

// DeleteHost deletes the host identified by id
func (s *Stack) DeleteHost(id string) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}

	_, domain, err := s.getHostAndDomainFromRef(id)
	if err != nil {
		return err
	}

	volumes, err := getVolumesFromDomain(domain, s.LibvirtService)
	if err != nil {
		return scerr.Errorf(fmt.Sprintf("failed to get the volumes from the domain : %s", err.Error()), err)
	}

	isActive, err := domain.IsActive()
	if err != nil {
		return scerr.Errorf(fmt.Sprintf("failed to know if the domain is active : %s", err.Error()), err)
	} else if !isActive {
		err := s.StartHost(id)
		if err != nil {
			return scerr.Errorf(fmt.Sprintf("failed to start the domain : %s", err.Error()), err)
		}
	}

	err = domain.Destroy()
	if err != nil {
		return scerr.Errorf(fmt.Sprintf("failed to destroy the domain : %s", err.Error()), err)
	}
	err = domain.Undefine()
	if err != nil {
		return scerr.Errorf(fmt.Sprintf("failed to undefine the domain : %s", err.Error()), err)
	}

	for _, volume := range volumes {
		volumePath := volume.Key
		pathSplitted := strings.Split(volumePath, "/")
		volumeName := strings.Split(pathSplitted[len(pathSplitted)-1], ".")[0]
		domainName, err := domain.GetName()
		if err != nil {
			return scerr.Errorf(fmt.Sprintf("failed to get domain name : %s", err.Error()), err)
		}
		if domainName == volumeName {
			err = s.DeleteVolume(volume.Name)
			if err != nil {
				return scerr.Errorf(fmt.Sprintf("failed to delete volume %s : %s", volumeName, err.Error()), err)
			}
		}
	}

	return nil
}

// ResizeHost change the template used by an host
func (s *Stack) ResizeHost(id string, request resources.SizingRequirements) (*resources.Host, error) {
	return nil, scerr.NotImplementedError("ResizeHost() not implemented yet") // FIXME Technical debt
}

// ListHosts lists available hosts
func (s *Stack) ListHosts() ([]*resources.Host, error) {
	var hosts []*resources.Host
	if s == nil {
		return hosts, scerr.InvalidInstanceError()
	}

	domains, err := s.LibvirtService.ListAllDomains(16383)
	if err != nil {
		return nil, scerr.Errorf(fmt.Sprintf(fmt.Sprintf("error listing domains : %s", err.Error())), err)
	}
	for _, domain := range domains {
		host, err := s.getHostFromDomain(&domain)
		if err != nil {
			return nil, scerr.Errorf(fmt.Sprintf(fmt.Sprintf("failed to get host from domain : %s", err.Error())), err)
		}

		hosts = append(hosts, host)
	}

	return hosts, nil
}

// StopHost stops the host identified by id
func (s *Stack) StopHost(id string) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}

	_, domain, err := s.getHostAndDomainFromRef(id)
	if err != nil {
		return scerr.Errorf(fmt.Sprintf(fmt.Sprintf("getHostAndDomainFromRef failed : %s", err.Error())), err)
	}

	err = domain.Shutdown()
	if err != nil {
		return scerr.Errorf(fmt.Sprintf(fmt.Sprintf("failed to shutdown the host : %s", err.Error())), err)
	}

	return nil
}

// StartHost starts the host identified by id
func (s *Stack) StartHost(id string) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}

	_, domain, err := s.getHostAndDomainFromRef(id)
	if err != nil {
		return scerr.Errorf(fmt.Sprintf(fmt.Sprintf("getHostAndDomainFromRef failed : %s", err.Error())), err)
	}

	err = domain.Create()
	if err != nil {
		return scerr.Errorf(fmt.Sprintf(fmt.Sprintf("failed to launch the host : %s", err.Error())), err)
	}

	return nil
}

// RebootHost reboot the host identified by id
func (s *Stack) RebootHost(id string) error {
	if s == nil {
		return scerr.InvalidInstanceError()
	}

	_, domain, err := s.getHostAndDomainFromRef(id)
	if err != nil {
		return scerr.Errorf(fmt.Sprintf(fmt.Sprintf("getHostAndDomainFromRef failed : %s", err.Error())), err)
	}

	err = domain.Reboot(0)
	if err != nil {
		return scerr.Errorf(fmt.Sprintf(fmt.Sprintf("failed to reboot the host : %s", err.Error())), err)
	}

	return nil
}

// GetHostState returns the host identified by id
func (s *Stack) GetHostState(hostParam interface{}) (hoststate.Enum, error) {
	if s == nil {
		return hoststate.ERROR, scerr.InvalidInstanceError()
	}

	host, err := s.InspectHost(hostParam)
	if err != nil {
		return hoststate.ERROR, err
	}
	return host.LastState, nil
}

// -------------Provider Infos-------------------------------------------------------------------------------------------

// ListAvailabilityZones lists the usable AvailabilityZones
func (s *Stack) ListAvailabilityZones() (map[string]bool, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	return map[string]bool{"local": true}, nil
}

func (s *Stack) ListRegions() ([]string, error) {
	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}

	return []string{"local"}, nil
}
