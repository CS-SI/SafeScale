/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package handlers

import (
	"context"

	"github.com/CS-SI/SafeScale/iaas"
	"github.com/CS-SI/SafeScale/iaas/resources"
)

//go:generate mockgen -destination=../mocks/mock_imageapi.go -package=mocks github.com/CS-SI/SafeScale/safescale/server/handlers ImageAPI

// TODO At service level, ve need to log before returning, because it's the last chance to track the real issue in server side

// ImageAPI defines API to manipulate images
type ImageAPI interface {
	List(ctx context.Context, all bool) ([]resources.Image, error)
	Select(ctx context.Context, osfilter string) (*resources.Image, error)
	Filter(ctx context.Context, osfilter string) ([]resources.Image, error)
}

// ImageHandler image service
type ImageHandler struct {
	service *iaas.Service
}

// NewImageHandler creates an host service
func NewImageHandler(svc *iaas.Service) ImageAPI {
	return &ImageHandler{
		service: svc,
	}
}

// List returns the image list
func (handler *ImageHandler) List(ctx context.Context, all bool) ([]resources.Image, error) {
	images, err := handler.service.ListImages(all)
	return images, infraErr(err)
}

// Select selects the image that best fits osname
func (handler *ImageHandler) Select(ctx context.Context, osname string) (*resources.Image, error) {
	return nil, nil
}

// Filter filters the images that do not fit osname
func (handler *ImageHandler) Filter(ctx context.Context, osname string) ([]resources.Image, error) {
	return nil, nil
}
