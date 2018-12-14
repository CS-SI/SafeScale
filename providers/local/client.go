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
	"fmt"

	libvirt "github.com/libvirt/libvirt-go"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/providers/model"
)

type Client struct {
	LibvirtService *libvirt.Connect

	Config      *CfgOptions
	AuthOptions *AuthOptions
}

type AuthOptions struct {
}
type CfgOptions struct {
	// MetadataBucketName contains the name of the bucket storing metadata
	MetadataBucketName        string
	ProviderNetwork           string
	AutoHostNetworkInterfaces bool
	UseLayer3Networking       bool
	ImagesJSONPath            string
	TemplatesJSONPath         string
	LibvirtStorage            string
}

// Build Create and initialize a ClientAPI
func (client *Client) Build(params map[string]interface{}) (api.ClientAPI, error) {
	clientAPI := &Client{
		Config: &CfgOptions{
			ProviderNetwork:           "default", //at least for qemu / KVM
			AutoHostNetworkInterfaces: false,
			UseLayer3Networking:       false,
		},
		AuthOptions: &AuthOptions{},
	}

	compute, _ := params["compute"].(map[string]interface{})

	uri, found := compute["uri"].(string)
	if !found {
		return nil, fmt.Errorf("Uri is not set")
	}
	libvirt, err := libvirt.NewConnect(uri)
	if err != nil {
		return nil, fmt.Errorf("Failed to connect to libvirt : %s", err.Error())
	}
	clientAPI.LibvirtService = libvirt

	if clientAPI.Config.MetadataBucketName == "" {
		clientAPI.Config.MetadataBucketName = metadata.BuildMetadataBucketName("id")
	}

	imagesJsonPath, found := compute["imagesJSONPath"].(string)
	if !found {
		return nil, fmt.Errorf("imagesJsonPath is not set")
	}
	templatesJsonPath, found := compute["templatesJSONPath"].(string)
	if !found {
		return nil, fmt.Errorf("templatesJsonPath is not set")
	}
	libvirtStorage, found := compute["libvirtStorage"].(string)
	if !found {
		return nil, fmt.Errorf("libvirtStorage is not set")
	}

	clientAPI.Config.ImagesJSONPath = imagesJsonPath
	clientAPI.Config.TemplatesJSONPath = templatesJsonPath
	clientAPI.Config.LibvirtStorage = libvirtStorage

	return clientAPI, nil
}

// GetAuthOpts returns authentification options as a Config
func (client *Client) GetAuthOpts() (model.Config, error) {
	cfg := model.ConfigMap{}

	return cfg, nil
}

// GetCfgOpts returns configuration options as a Config
func (client *Client) GetCfgOpts() (model.Config, error) {
	config := model.ConfigMap{}

	config.Set("AutoHostNetworkInterfaces", client.Config.AutoHostNetworkInterfaces)
	config.Set("UseLayer3Networking", client.Config.UseLayer3Networking)
	config.Set("MetadataBucket", client.Config.MetadataBucketName)
	config.Set("ProviderNetwork", client.Config.ProviderNetwork)

	return config, nil
}

func init() {
	providers.Register("local", &Client{})
}
