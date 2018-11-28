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

package services

import (
	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/model"
)

//go:generate mockgen -destination=../mocks/mock_imageapi.go -package=mocks github.com/CS-SI/SafeScale/broker/server/services ImageAPI

// TODO At service level, ve need to log before returning, because it's the last chance to track the real issue in server side

// ImageAPI defines API to manipulate hosts
type ImageAPI interface {
	List(all bool) ([]model.Image, error)
	Select(osfilter string) (*model.Image, error)
	Filter(osfilter string) ([]model.Image, error)
}

//NewImageService creates an host service
func NewImageService(api *providers.Service) ImageAPI {
	return &ImageService{
		provider: api,
	}
}

// ImageService image service
type ImageService struct {
	provider *providers.Service
}

// List returns the image list
func (srv *ImageService) List(all bool) ([]model.Image, error) {
	images, err := srv.provider.ListImages(all)
	return images, infraErr(err)
}

// Select selects the image that best fits osname
func (srv *ImageService) Select(osname string) (*model.Image, error) {
	return nil, nil
}

// Filter filters the images that do not fit osname
func (srv *ImageService) Filter(osname string) ([]model.Image, error) {
	return nil, nil
}
