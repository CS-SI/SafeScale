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
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostProperty"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostState"
	"github.com/CS-SI/SafeScale/providers/model/enums/IPVersion"
	propsv1 "github.com/CS-SI/SafeScale/providers/model/properties/v1"
	"github.com/CS-SI/SafeScale/providers/userdata"
	"github.com/CS-SI/SafeScale/utils/retry"
	"golang.org/x/crypto/ssh"

	libvirt "github.com/libvirt/libvirt-go"
	libvirtxml "github.com/libvirt/libvirt-go-xml"
	uuid "github.com/satori/go.uuid"
)

// The createds hosts could be connected to the network with a bridge or a nat
// CAUTION the bridged VMs needs the default route to be a macVlan interface!
// On centos the firewall bloks all ports by default so the vm will not be alble to send back usefull infos
// sudo firewall-cmd --zone=public --permanent --add-port=1000-63553/tcp
// sudo firewall-cmd --reload
var bridgedVMs = false

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

//-------------IMAGES---------------------------------------------------------------------------------------------------

// ListImages lists available OS images
func (client *Client) ListImages(all bool) ([]model.Image, error) {
	if !all {
		//TODO implement list images all
	}

	jsonFile, err := os.Open(client.Config.ImagesJSONPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to open %s : %s", client.Config.ImagesJSONPath, err.Error())
	}
	defer func() {
		if err := jsonFile.Close(); err != nil {
			fmt.Println("Failed to close images file")
		}
	}()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, fmt.Errorf("Failed to read %s : %s", client.Config.ImagesJSONPath, err.Error())
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(byteValue), &result); err != nil {
		return nil, fmt.Errorf("Failed to unmarshal jsonFile %s : %s", client.Config.ImagesJSONPath, err.Error())
	}

	imagesJSON := result["images"].([]interface{})
	images := []model.Image{}
	for _, imageJSON := range imagesJSON {
		image := model.Image{
			ID:   imageJSON.(map[string]interface{})["imageID"].(string),
			Name: imageJSON.(map[string]interface{})["imageName"].(string),
		}
		images = append(images, image)
	}

	return images, nil
}

// GetImage returns the Image referenced by id
func (client *Client) GetImage(id string) (*model.Image, error) {
	jsonFile, err := os.Open(client.Config.ImagesJSONPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to open %s : %s", client.Config.ImagesJSONPath, err.Error())
	}
	defer func() {
		if err := jsonFile.Close(); err != nil {
			fmt.Println("Failed to close images file")
		}
	}()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, fmt.Errorf("Failed to read %s : %s", client.Config.ImagesJSONPath, err.Error())
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(byteValue), &result); err != nil {
		return nil, fmt.Errorf("Failed to unmarshal jsonFile %s : %s", client.Config.ImagesJSONPath, err.Error())
	}

	imagesJSON := result["images"].([]interface{})
	for _, imageJSON := range imagesJSON {
		if imageID, ok := imageJSON.(map[string]interface{})["imageID"]; ok && imageID == id {
			return &model.Image{
				ID:   imageJSON.(map[string]interface{})["imageID"].(string),
				Name: imageJSON.(map[string]interface{})["imageName"].(string),
			}, nil
		}
		if imageName, ok := imageJSON.(map[string]interface{})["imageName"]; ok && imageName == id {
			return &model.Image{
				ID:   imageJSON.(map[string]interface{})["imageID"].(string),
				Name: imageJSON.(map[string]interface{})["imageName"].(string),
			}, nil
		}
	}

	return nil, fmt.Errorf("Image with id=%s not found", id)
}

//-------------TEMPLATES------------------------------------------------------------------------------------------------

// ListTemplates overload OpenStack ListTemplate method to filter wind and flex instance and add GPU configuration
func (client *Client) ListTemplates(all bool) ([]model.HostTemplate, error) {
	if !all {
		//TODO implement list images all
	}

	jsonFile, err := os.Open(client.Config.TemplatesJSONPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to open %s : %s", client.Config.TemplatesJSONPath, err.Error())
	}
	defer func() {
		if err := jsonFile.Close(); err != nil {
			fmt.Println("Failed to close template file")
		}
	}()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, fmt.Errorf("Failed to read %s : %s", client.Config.TemplatesJSONPath, err.Error())
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(byteValue), &result); err != nil {
		return nil, fmt.Errorf("Failed to unmarshal jsonFile %s : %s", client.Config.TemplatesJSONPath, err.Error())
	}

	templatesJSON := result["templates"].([]interface{})
	templates := []model.HostTemplate{}
	for _, templateJSON := range templatesJSON {
		template := model.HostTemplate{
			HostTemplate: &propsv1.HostTemplate{
				HostSize: &propsv1.HostSize{
					Cores:     int(templateJSON.(map[string]interface{})["templateSpecs"].(map[string]interface{})["coresNumber"].(float64)),
					RAMSize:   float32(templateJSON.(map[string]interface{})["templateSpecs"].(map[string]interface{})["ramSize"].(float64)),
					DiskSize:  int(templateJSON.(map[string]interface{})["templateSpecs"].(map[string]interface{})["diskSize"].(float64)),
					GPUNumber: int(templateJSON.(map[string]interface{})["templateSpecs"].(map[string]interface{})["gpuNumber"].(float64)),
					GPUType:   templateJSON.(map[string]interface{})["templateSpecs"].(map[string]interface{})["gpuType"].(string),
				},
				ID:   templateJSON.(map[string]interface{})["templateID"].(string),
				Name: templateJSON.(map[string]interface{})["templateName"].(string),
			},
		}
		templates = append(templates, template)
	}

	return templates, nil
}

//GetTemplate overload OpenStack GetTemplate method to add GPU configuration
func (client *Client) GetTemplate(id string) (*model.HostTemplate, error) {
	jsonFile, err := os.Open(client.Config.TemplatesJSONPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to open %s : %s", client.Config.TemplatesJSONPath, err.Error())
	}
	defer func() {
		if err := jsonFile.Close(); err != nil {
			fmt.Println("Failed to close template file")
		}
	}()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, fmt.Errorf("Failed to read %s : %s", client.Config.TemplatesJSONPath, err.Error())
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(byteValue), &result); err != nil {
		return nil, fmt.Errorf("Failed to unmarshal jsonFile %s : %s", client.Config.TemplatesJSONPath, err.Error())
	}

	templatesJSON := result["templates"].([]interface{})
	for _, templateJSON := range templatesJSON {
		if templateID, _ := templateJSON.(map[string]interface{})["templateID"]; templateID == id {
			return &model.HostTemplate{
				HostTemplate: &propsv1.HostTemplate{
					HostSize: &propsv1.HostSize{
						Cores:     int(templateJSON.(map[string]interface{})["templateSpecs"].(map[string]interface{})["coresNumber"].(float64)),
						RAMSize:   float32(templateJSON.(map[string]interface{})["templateSpecs"].(map[string]interface{})["ramSize"].(float64)),
						DiskSize:  int(templateJSON.(map[string]interface{})["templateSpecs"].(map[string]interface{})["diskSize"].(float64)),
						GPUNumber: int(templateJSON.(map[string]interface{})["templateSpecs"].(map[string]interface{})["gpuNumber"].(float64)),
						GPUType:   templateJSON.(map[string]interface{})["templateSpecs"].(map[string]interface{})["gpuType"].(string),
					},
					ID:   templateJSON.(map[string]interface{})["templateID"].(string),
					Name: templateJSON.(map[string]interface{})["templateName"].(string),
				},
			}, nil
		}
	}

	return nil, fmt.Errorf("Template with id=%s not found", id)
}

//-------------SSH KEYS-------------------------------------------------------------------------------------------------

// CreateKeyPair creates and import a key pair
func (client *Client) CreateKeyPair(name string) (*model.KeyPair, error) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := privateKey.PublicKey
	pub, _ := ssh.NewPublicKey(&publicKey)
	pubBytes := ssh.MarshalAuthorizedKey(pub)
	pubKey := string(pubBytes)

	priBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	priKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: priBytes,
		},
	)

	priKey := string(priKeyPem)
	uuid, err := uuid.NewV4()
	if err != nil {
		return nil, fmt.Errorf("Failed to generate uuid key : %s", err.Error())
	}
	return &model.KeyPair{
		ID:         uuid.String(),
		Name:       name,
		PublicKey:  pubKey,
		PrivateKey: priKey,
	}, nil
}

// GetKeyPair returns the key pair identified by id
func (client *Client) GetKeyPair(id string) (*model.KeyPair, error) {
	return nil, fmt.Errorf("Not implemented")
}

// ListKeyPairs lists available key pairs
func (client *Client) ListKeyPairs() ([]model.KeyPair, error) {
	return nil, fmt.Errorf("Not implemented")
}

// DeleteKeyPair deletes the key pair identified by id
func (client *Client) DeleteKeyPair(id string) error {
	return fmt.Errorf("Not implemented")
}

//-------------HOST MANAGEMENT------------------------------------------------------------------------------------------
func downloadImage(path string, downloadInfo map[string]interface{}) error {
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
			return fmt.Errorf("Commands failed : \n%s\n%s", command, err.Error())
		}
	default:
		return fmt.Errorf("download method %s not implemented", downloadInfo["method"].(string))
	}
	return nil
}

// getImagePathFromID retrieve the storage path of an image from this image ID
func getImagePathFromID(client *Client, id string) (string, error) {
	jsonFile, err := os.Open(client.Config.ImagesJSONPath)
	if err != nil {
		return "", fmt.Errorf("Failed to open %s : %s", client.Config.ImagesJSONPath, err.Error())
	}
	defer func() {
		if err := jsonFile.Close(); err != nil {
			fmt.Println("Failed to close image file")
		}
	}()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return "", fmt.Errorf("Failed to read %s : %s", client.Config.ImagesJSONPath, err.Error())
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(byteValue), &result); err != nil {
		return "", fmt.Errorf("Failed to unmarshal jsonFile %s : %s", client.Config.ImagesJSONPath, err.Error())
	}

	imagesJSON := result["images"].([]interface{})
	for _, imageJSON := range imagesJSON {
		if imageID, _ := imageJSON.(map[string]interface{})["imageID"]; imageID == id {
			path := imageJSON.(map[string]interface{})["imagePath"].(string)
			if _, err := os.Stat(path); os.IsNotExist(err) {
				err := downloadImage(path, imageJSON.(map[string]interface{})["download"].(map[string]interface{}))
				if err != nil {
					return "", fmt.Errorf("Failed to download image : %s", err.Error())
				}
			} else if err != nil {
				return "", fmt.Errorf("Unable to check if the file %s exists or not : %s", filepath.Base(path), err.Error())
			}
			return path, nil
		}
	}

	return "", fmt.Errorf("Image with id=%s not found", id)
}

// getDiskFromID retrieve the disk with root partition of an image from this image ID
func getDiskFromID(client *Client, id string) (string, error) {
	jsonFile, err := os.Open(client.Config.ImagesJSONPath)
	if err != nil {
		return "", fmt.Errorf("Failed to open %s : %s", client.Config.ImagesJSONPath, err.Error())
	}
	defer func() {
		if err := jsonFile.Close(); err != nil {
			fmt.Println("Failed to close image file")
		}
	}()

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return "", fmt.Errorf("Failed to read %s : %s", client.Config.ImagesJSONPath, err.Error())
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(byteValue), &result); err != nil {
		return "", fmt.Errorf("Failed to unmarshal jsonFile %s : %s", client.Config.ImagesJSONPath, err.Error())
	}

	imagesJSON := result["images"].([]interface{})
	for _, imageJSON := range imagesJSON {
		if imageID, _ := imageJSON.(map[string]interface{})["imageID"]; imageID == id {
			return imageJSON.(map[string]interface{})["disk"].(string), nil
		}
	}

	return "", fmt.Errorf("Image with id=%s not found", id)
}

func getVolumesFromDomain(domain *libvirt.Domain, libvirtService *libvirt.Connect) ([]*libvirtxml.StorageVolume, error) {
	volumeDescriptions := []*libvirtxml.StorageVolume{}
	domainVolumePaths := []string{}

	//List paths of domain disks
	domainXML, err := domain.GetXMLDesc(0)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Failed get xml description of a domain : %s", err.Error()))
	}
	domainDescription := &libvirtxml.Domain{}
	err = xml.Unmarshal([]byte(domainXML), domainDescription)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Failed unmarshall the domain description : %s", err.Error()))
	}
	domainDisks := domainDescription.Devices.Disks

	for _, disk := range domainDisks {
		domainVolumePaths = append(domainVolumePaths, disk.Source.File.File)
	}

	//Check which volumes match these paths
	pools, err := libvirtService.ListAllStoragePools(2)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Failed list pools : %s", err.Error()))
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
				return nil, fmt.Errorf(fmt.Sprintf("Failed unmarshall the volume description : %s", err.Error()))
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

//stateConvert convert libvirt.DomainState to a HostState.Enum
func stateConvert(stateLibvirt libvirt.DomainState) HostState.Enum {
	switch stateLibvirt {
	case 1:
		return HostState.STARTED
	case 3, 5:
		return HostState.STOPPED
	case 4:
		return HostState.STOPPING
	default:
		return HostState.ERROR
	}
}

func getDescriptionV1FromDomain(domain *libvirt.Domain, libvirtService *libvirt.Connect) (*propsv1.HostDescription, error) {
	hostDescription := propsv1.NewHostDescription()

	//var Created time.Time
	//var Creator string
	//var Updated time.Time
	//var Purpose string

	//There is a creation and modification timestamp on disks but it'not the best way to get the vm creation / modification date

	return hostDescription, nil
}
func getSizingV1FromDomain(domain *libvirt.Domain, libvirtService *libvirt.Connect) (*propsv1.HostSizing, error) {
	hostSizing := propsv1.NewHostSizing()

	info, err := domain.GetInfo()
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Failed to get infos from the domain : %s", err.Error()))
	}

	diskSize := 0
	volumes, err := getVolumesFromDomain(domain, libvirtService)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Failed to get volumes from the domain : %s", err.Error()))
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

	//hostSizing.RequestedSize and hostSizing.Template are unknown by libvirt and are left unset

	return hostSizing, nil
}
func (client *Client) getNetworkV1FromDomain(domain *libvirt.Domain) (*propsv1.HostNetwork, error) {
	hostNetwork := propsv1.NewHostNetwork()

	domainXML, err := domain.GetXMLDesc(0)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Failed get xml description of a domain : %s", err.Error()))
	}
	domainDescription := &libvirtxml.Domain{}
	err = xml.Unmarshal([]byte(domainXML), domainDescription)

	networks, err := client.LibvirtService.ListAllNetworks(3)
	if err != nil {
		return nil, fmt.Errorf("Failed to list all networks : %s", err.Error())
	}

	for _, iface := range domainDescription.Devices.Interfaces {
		if iface.Source.Network != nil {
			err = retry.WhileUnsuccessfulDelay5Seconds(
				func() error {
					for _, network := range networks {
						name, err := network.GetName()
						if err != nil {
							return fmt.Errorf("Failed to get network name : %s", err.Error())
						}
						if name == iface.Source.Network.Network {
							dhcpLeases, err := network.GetDHCPLeases()
							if err != nil {
								return fmt.Errorf("Failed to get network dhcpLeases : %s", err.Error())
							}
							for _, dhcpLease := range dhcpLeases {
								if dhcpLease.Mac == iface.MAC.Address {
									net, err := client.GetNetwork(iface.Source.Network.Network)
									if err != nil {
										return fmt.Errorf("Unknown Network %s", iface.Source.Network.Network)
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
										return fmt.Errorf("Unknown adressType")
									}
									hostNetwork.NetworksByID[net.ID] = net.Name
									hostNetwork.NetworksByName[net.Name] = net.ID
									return nil
								}
							}
						}
					}
					return fmt.Errorf("No local IP matching inteface %s found", iface.Alias)
				},
				5*time.Minute,
			)

		}
	}
	return hostNetwork, nil
}

// getHostFromDomain build a model.Host struct representing a Domain
func (client *Client) getHostFromDomain(domain *libvirt.Domain) (*model.Host, error) {
	id, err := domain.GetUUIDString()
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Failed to fetch id from domain : %s", err.Error()))
	}
	name, err := domain.GetName()
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Failed to fetch name from domain : %s", err.Error()))
	}
	state, _, err := domain.GetState()
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Failed to fetch state from domain : %s", err.Error()))
	}
	hostDescriptionV1, err := getDescriptionV1FromDomain(domain, client.LibvirtService)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Failed to get domain description : %s", err.Error()))
	}
	hostSizingV1, err := getSizingV1FromDomain(domain, client.LibvirtService)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Failed to get domain sizing : %s", err.Error()))
	}
	hostNetworkV1, err := client.getNetworkV1FromDomain(domain)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Failed to get domain networks: %s", err.Error()))
	}

	host := model.NewHost()

	host.ID = id
	host.Name = name
	host.PrivateKey = "Impossible to fetch them from the domain, the private key is unknown by the domain"
	host.LastState = stateConvert(state)
	if err := host.Properties.Set(HostProperty.DescriptionV1, hostDescriptionV1); err != nil {
		return nil, fmt.Errorf("Failed to set HostProperty.DescriptionV1 : %s", err.Error())
	}
	if err := host.Properties.Set(HostProperty.SizingV1, hostSizingV1); err != nil {
		return nil, fmt.Errorf("Failed to set HostProperty.SizingV1 : %s", err.Error())
	}
	if err := host.Properties.Set(HostProperty.NetworkV1, hostNetworkV1); err != nil {
		return nil, fmt.Errorf("Failed to set HostProperty.NetworkV1 : %s", err.Error())
	}

	return host, nil
}

// getHostAndDomainFromRef retrieve the host and the domain associated to an ref (id or name)
func (client *Client) getHostAndDomainFromRef(ref string) (*model.Host, *libvirt.Domain, error) {
	domain, err := client.LibvirtService.LookupDomainByUUIDString(ref)
	if err != nil {
		domain, err = client.LibvirtService.LookupDomainByName(ref)
		if err != nil {
			re, err2 := regexp.Compile("[0-9]+")
			if err2 != nil {
				return nil, nil, fmt.Errorf(fmt.Sprintf("Failed to fetch domain from ref : %s", err.Error()))
			}
			errCode, _ := strconv.Atoi(re.FindString(err.Error()))
			if errCode == 42 {
				return nil, nil, model.ResourceNotFoundError("host", ref)
			}
			return nil, nil, fmt.Errorf(fmt.Sprintf("Failed to fetch domain from ref : %s", err.Error()))
		}
	}
	host, err := client.getHostFromDomain(domain)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to get host from domain : %s", err.Error())
	}

	return host, domain, nil
}

func (client *Client) complementHost(host *model.Host, newHost *model.Host) error {
	if host == nil || newHost == nil {
		return fmt.Errorf("host and newHost have to been set")
	}

	host.ID = newHost.ID
	if host.Name == "" {
		host.Name = newHost.Name
	}
	host.LastState = newHost.LastState

	hpNetworkV1 := propsv1.NewHostNetwork()
	err := host.Properties.Get(HostProperty.NetworkV1, hpNetworkV1)
	if err != nil {
		return err
	}
	newhpNetworkV1 := propsv1.NewHostNetwork()
	err = newHost.Properties.Get(HostProperty.NetworkV1, newhpNetworkV1)
	if err != nil {
		return err
	}
	hpNetworkV1.IPv4Addresses = newhpNetworkV1.IPv4Addresses
	hpNetworkV1.IPv6Addresses = newhpNetworkV1.IPv6Addresses
	hpNetworkV1.NetworksByID = newhpNetworkV1.NetworksByID
	hpNetworkV1.NetworksByName = newhpNetworkV1.NetworksByName
	err = host.Properties.Set(HostProperty.NetworkV1, hpNetworkV1)
	if err != nil {
		return err
	}

	hpSizingV1 := propsv1.NewHostSizing()
	err = host.Properties.Get(HostProperty.SizingV1, hpSizingV1)
	if err != nil {
		return err
	}
	newhpSizingV1 := propsv1.NewHostSizing()
	err = newHost.Properties.Get(HostProperty.SizingV1, newhpSizingV1)
	if err != nil {
		return err
	}
	hpSizingV1.AllocatedSize.Cores = newhpSizingV1.AllocatedSize.Cores
	hpSizingV1.AllocatedSize.RAMSize = newhpSizingV1.AllocatedSize.RAMSize
	hpSizingV1.AllocatedSize.DiskSize = newhpSizingV1.AllocatedSize.DiskSize
	err = host.Properties.Set(HostProperty.SizingV1, hpSizingV1)
	if err != nil {
		return err
	}

	return nil
}

// CreateHost creates an host satisfying request
func (client *Client) CreateHost(request model.HostRequest) (*model.Host, error) {
	resourceName := request.ResourceName
	hostName := request.HostName
	networks := request.Networks
	publicIP := request.PublicIP
	templateID := request.TemplateID
	imageID := request.ImageID
	keyPair := request.KeyPair
	defaultGateway := request.DefaultGateway

	//----Check Inputs----
	if resourceName == "" {
		return nil, fmt.Errorf("The ResourceName is mandatory ")
	}
	if hostName == "" {
		hostName = resourceName
	}
	if networks == nil || len(networks) == 0 {
		return nil, fmt.Errorf("The host %s must be on at least one network (even if public)", resourceName)
	}
	if defaultGateway == nil && !publicIP {
		return nil, fmt.Errorf("The host %s must have a gateway or be public", resourceName)
	}
	if templateID == "" {
		return nil, fmt.Errorf("The TemplateID is mandatory")
	}
	if imageID == "" {
		return nil, fmt.Errorf("The ImageID is mandatory")
	}
	host, _, err := client.getHostAndDomainFromRef(resourceName)
	if err == nil && host != nil {
		return nil, fmt.Errorf("The Host %s already exists", resourceName)
	}

	//----Initialize----
	if keyPair == nil {
		var err error
		keyPair, err = client.CreateKeyPair(fmt.Sprintf("key_%s", resourceName))
		if err != nil {
			return nil, fmt.Errorf("KeyPair creation failed : %s", err.Error())
		}
	}
	template, err := client.GetTemplate(templateID)
	if err != nil {
		return nil, fmt.Errorf("GetTemplate failed : %s", err.Error())
	}
	imagePath, err := getImagePathFromID(client, imageID)
	if err != nil {
		return nil, fmt.Errorf("GetImagePathFromID failled %s: ", err.Error())
	}
	imageDisk, err := getDiskFromID(client, imageID)
	if err != nil {
		return nil, fmt.Errorf("GetDiskFromID failled %s: ", err.Error())
	}

	userData, err := userdata.Prepare(client, request, keyPair, networks[0].CIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare user data content: %+v", err)
	}

	//----Commands----
	var vmInfoChannel (chan VMInfo)
	networksCommandString := ""
	for _, network := range networks {
		networksCommandString += fmt.Sprintf(" --network network=%s", network.Name)
	}
	if publicIP {
		command := ""
		if bridgedVMs {
			command = "ip route get 8.8.8.8 |awk -F\"src \" 'NR==1{split($2,a,\" \");print a[1]}'"
		} else {
			networkDefault, err := client.GetNetwork("default")
			if err != nil {
				switch err.(type) {
				case model.ErrResourceNotFound:
					networkDefault, err = client.CreateNetwork(
						model.NetworkRequest{
							Name:      "default",
							IPVersion: IPVersion.IPv4,
							CIDR:      "192.168.150.0/24",
						},
					)
					if err != nil {
						return nil, fmt.Errorf("failure To create network default : %s ", err.Error())
					}
				default:
					return nil, fmt.Errorf("failure To get network default : %s ", err.Error())
				}
			}

			command = "ip route | grep " + networkDefault.CIDR + " |awk -F\"src \" 'NR==1{split($2,a,\" \");print a[1]}'"
		}
		cmd := exec.Command("bash", "-c", command)
		cmdOutput := &bytes.Buffer{}
		cmd.Stdout = cmdOutput
		err = cmd.Run()
		if err != nil {
			return nil, fmt.Errorf("Commands failed : \n%s\n%s", command, err.Error())
		}
		ip := strings.Trim(fmt.Sprint(cmdOutput), "\n ")

		if bridgedVMs {
			infoWaiter, err := GetInfoWaiter()
			if err != nil {
				return nil, fmt.Errorf("failed to get info waiter : %s", err.Error())
			}

			userData = userdata.Append(userData, fmt.Sprintf(`
LANIP=$(ip route get 8.8.8.8 | awk -F"src " 'NR==1{split($2,a," ");print a[1]}')
echo -n "%s|$LANIP" > /dev/tcp/%s/%d`, hostName, ip, infoWaiter.port))

			command = "ip route get 8.8.8.8 | awk -F\"dev \" 'NR==1{split($2,a,\" \");print a[1]}'"
			cmd = exec.Command("bash", "-c", command)
			cmdOutput = &bytes.Buffer{}
			cmd.Stdout = cmdOutput
			err = cmd.Run()
			if err != nil {
				return nil, fmt.Errorf("Commands failed : \n%s\n%s", command, err.Error())
			}
			lanIf := strings.Trim(fmt.Sprint(cmdOutput), "\n ")
			networksCommandString += fmt.Sprintf(" --network type=direct,source=%s,source_mode=bridge", lanIf)
			vmInfoChannel = infoWaiter.Register(hostName)
		} else {
			networksCommandString += fmt.Sprintf(" --network network=default")
		}

	}

	userdataFileName := client.Config.LibvirtStorage + "/" + resourceName + "_userdata.sh"
	err = ioutil.WriteFile(userdataFileName, userData, 0644)
	if err != nil {
		return nil, fmt.Errorf("Failed to write userData in %s_userdata.sh file : %s", resourceName, err.Error())
	}

	// without sudo rights /boot/vmlinuz/`uname -r` have to be readable by the user to execute virt-resize / virt-sysprep
	// TODO gpu is ignored
	// TODO use libvirt-go functions not bash commands
	commandSetup := fmt.Sprintf("IMAGE_PATH=\"%s\" && IMAGE=\"`echo $IMAGE_PATH | rev | cut -d/ -f1 | rev`\" && EXT=\"`echo $IMAGE | grep -o '[^.]*$'`\" && LIBVIRT_STORAGE=\"%s\" && HOST_NAME=\"%s\" && VM_IMAGE=\"$LIBVIRT_STORAGE/$HOST_NAME.$EXT\"", imagePath, client.Config.LibvirtStorage, resourceName)
	commandResize := fmt.Sprintf("cd $LIBVIRT_STORAGE && chmod 666 $IMAGE_PATH && truncate $VM_IMAGE -s %dG && virt-resize --expand %s $IMAGE_PATH $VM_IMAGE", template.DiskSize, imageDisk)
	commandSysprep := fmt.Sprintf("virt-sysprep -a $VM_IMAGE --hostname %s --operations defaults,-ssh-hostkeys --firstboot %s && rm %s", hostName, userdataFileName, userdataFileName)
	commandVirtInstall := fmt.Sprintf("virt-install --connect \"%s\" --noautoconsole --name=%s --vcpus=%d --memory=%d --import --disk=$VM_IMAGE %s", client.Config.URI, resourceName, template.Cores, int(template.RAMSize*1024), networksCommandString)
	command := strings.Join([]string{commandSetup, commandResize, commandSysprep, commandVirtInstall}, " && ")

	cmd := exec.Command("bash", "-c", command)

	cmdOutput := &bytes.Buffer{}
	cmd.Stdout = cmdOutput
	err = cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("Commands failed : \n%s\n%s", command, err.Error())
	}

	defer func() {
		if err != nil {
			if err := client.DeleteHost(resourceName); err != nil {
				fmt.Printf("Failed to Delete the host %s : %s", resourceName, err.Error())
			}
		}
	}()

	//----Generate model.Host----

	domain, err := client.LibvirtService.LookupDomainByName(resourceName)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Can't find domain %s : %s", resourceName, err.Error()))
	}

	host, err = client.getHostFromDomain(domain)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Failed to get host %s from domain : %s", resourceName, err.Error()))
	}

	host.PrivateKey = keyPair.PrivateKey

	hostNetworkV1 := propsv1.NewHostNetwork()
	if err := host.Properties.Get(HostProperty.NetworkV1, hostNetworkV1); err != nil {
		return nil, fmt.Errorf("Failed to get the HostProperty.NetworkV1 : %s", err.Error())
	}

	if bridgedVMs {
		var vmInfo VMInfo
		if publicIP {
			vmInfo = <-vmInfoChannel
			hostNetworkV1.PublicIPv4 = vmInfo.publicIP
		}
	}

	hostNetworkV1.DefaultNetworkID = request.Networks[0].ID
	hostNetworkV1.IsGateway = request.DefaultGateway == nil && request.Networks[0].Name != model.SingleHostNetworkName
	if request.DefaultGateway != nil {
		hostNetworkV1.DefaultGatewayID = request.DefaultGateway.ID

		gateway, err := client.GetHost(request.DefaultGateway)
		if err != nil {
			return nil, fmt.Errorf("Failed to get gateway host : %s", err.Error())
		}

		hostNetworkV1.DefaultGatewayPrivateIP = gateway.GetPrivateIP()
	}

	hostSizingV1 := propsv1.NewHostSizing()
	if err := host.Properties.Get(HostProperty.SizingV1, hostSizingV1); err != nil {
		return nil, fmt.Errorf("Failed to get the HostProperty.SizingV1 : %s", err.Error())
	}

	hostSizingV1.RequestedSize.RAMSize = float32(template.RAMSize * 1024)
	hostSizingV1.RequestedSize.Cores = template.Cores
	hostSizingV1.RequestedSize.DiskSize = template.DiskSize
	// TODO GPU not implemented
	hostSizingV1.RequestedSize.GPUNumber = template.GPUNumber
	hostSizingV1.RequestedSize.GPUType = template.GPUType

	if err := host.Properties.Set(HostProperty.NetworkV1, hostNetworkV1); err != nil {
		return nil, fmt.Errorf("Failed to set the HostProperty.NetworkV1 : %s", err.Error())
	}
	if err := host.Properties.Set(HostProperty.SizingV1, hostSizingV1); err != nil {
		return nil, fmt.Errorf("Failed to set the HostProperty.SizingV1 : %s", err.Error())
	}

	return host, nil
}

// GetHost returns the host identified by ref (name or id) or by a *model.Host containing an id
func (client *Client) GetHost(hostParam interface{}) (*model.Host, error) {
	var host *model.Host

	switch hostParam.(type) {
	case string:
		host = model.NewHost()
		host.ID = hostParam.(string)
	case *model.Host:
		host = hostParam.(*model.Host)
	default:
		panic("host must be a string or a *model.Host!")
	}

	newHost, _, err := client.getHostAndDomainFromRef(host.ID)
	if err != nil {
		return nil, err
	}

	if err := client.complementHost(host, newHost); err != nil {
		return nil, fmt.Errorf("Failed to complement the host : %s", err.Error())
	}

	return host, nil
}

// GetHostByName returns the host identified by ref (name or id)
func (client *Client) GetHostByName(name string) (*model.Host, error) {
	return client.GetHost(name)
}

// DeleteHost deletes the host identified by id
func (client *Client) DeleteHost(id string) error {
	_, domain, err := client.getHostAndDomainFromRef(id)
	if err != nil {
		return err
	}

	volumes, err := getVolumesFromDomain(domain, client.LibvirtService)
	if err != nil {
		return fmt.Errorf("Failed to get the volumes from the domain : %s", err.Error())
	}

	isActive, err := domain.IsActive()
	if err != nil {
		return fmt.Errorf("Failed to know if the domain is active : %s", err.Error())
	} else if !isActive {
		err := client.StartHost(id)
		if err != nil {
			return fmt.Errorf("Failed to start the domain : %s", err.Error())
		}
	}

	err = domain.Destroy()
	if err != nil {
		return fmt.Errorf("Failed to destroy the domain : %s", err.Error())
	}
	err = domain.Undefine()
	if err != nil {
		return fmt.Errorf("Failed to undefine the domain : %s", err.Error())
	}

	for _, volume := range volumes {
		volumePath := volume.Key
		pathSplitted := strings.Split(volumePath, "/")
		volumeName := strings.Split(pathSplitted[len(pathSplitted)-1], ".")[0]
		domainName, err := domain.GetName()
		if err != nil {
			return fmt.Errorf("Failed to get domain name : %s", err.Error())
		}
		if domainName == volumeName {
			err = client.DeleteVolume(volume.Name)
			if err != nil {
				return fmt.Errorf("Failed to delete volume %s : %s", volumeName, err.Error())
			}
		}
	}

	return nil
}

// ResizeHost change the template used by an host
func (client *Client) ResizeHost(id string, request model.SizingRequirements) (*model.Host, error) {
	return nil, fmt.Errorf("Not implemented yet")
}

// ListHosts lists available hosts
func (client *Client) ListHosts() ([]*model.Host, error) {
	var hosts []*model.Host

	domains, err := client.LibvirtService.ListAllDomains(16383)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Error listing domains : %s", err.Error()))
	}
	for _, domain := range domains {
		host, err := client.getHostFromDomain(&domain)
		if err != nil {
			return nil, fmt.Errorf(fmt.Sprintf("Failed to get host from domain : %s", err.Error()))
		}

		hosts = append(hosts, host)
	}

	return hosts, nil
}

// StopHost stops the host identified by id
func (client *Client) StopHost(id string) error {
	_, domain, err := client.getHostAndDomainFromRef(id)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("getHostAndDomainFromRef failed : %s", err.Error()))
	}

	err = domain.Shutdown()
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("Failed to shutdown the host : %s", err.Error()))
	}

	return nil
}

// StartHost starts the host identified by id
func (client *Client) StartHost(id string) error {
	_, domain, err := client.getHostAndDomainFromRef(id)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("getHostAndDomainFromRef failed : %s", err.Error()))
	}

	err = domain.Create()
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("Failed to launch the host : %s", err.Error()))
	}

	return nil
}

// RebootHost reboot the host identified by id
func (client *Client) RebootHost(id string) error {
	_, domain, err := client.getHostAndDomainFromRef(id)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("getHostAndDomainFromRef failed : %s", err.Error()))
	}

	err = domain.Reboot(0)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("Failed to reboot the host : %s", err.Error()))
	}

	return nil
}

// GetHostState returns the host identified by id
func (client *Client) GetHostState(hostParam interface{}) (HostState.Enum, error) {
	host, err := client.GetHost(hostParam)
	if err != nil {
		return HostState.ERROR, err
	}
	return host.LastState, nil
}

//-------------Provider Infos-------------------------------------------------------------------------------------------

// ListAvailabilityZones lists the usable AvailabilityZones
func (client *Client) ListAvailabilityZones(all bool) (map[string]bool, error) {
	return map[string]bool{"local": true}, nil
}
