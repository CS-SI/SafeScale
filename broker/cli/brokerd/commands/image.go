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

package commands

import (
	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
)

// broker host create host1 --net="net1" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" --public=true
// broker host list
// broker host inspect host1
// broker host create host2 --net="net1" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" --public=false

//ImageAPI defines API to manipulate images
type ImageAPI interface {
	List() ([]api.Image, error)
	Select(osfilter string) (*api.Image, error)
	Filter(osfilter string) ([]api.Image, error)
}

//NewImageService creates an Image service
func NewImageService(api api.ClientAPI) ImageAPI {
	return &ImageService{
		provider: providers.FromClient(api),
	}
}

//ImageService host service
type ImageService struct {
	provider *providers.Service
}

//List list all images
func (srv *ImageService) List() ([]api.Image, error) {
	return srv.provider.ListImages()
}

//Select selects the image that best fits osname
func (srv *ImageService) Select(osname string) (*api.Image, error) {
	return nil, nil
}

//Filter filters the images that do not fit osname
func (srv *ImageService) Filter(osname string) ([]api.Image, error) {
	return nil, nil
}
