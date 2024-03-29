/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/v22/lib/backend"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/backend/handlers.ImageHandler -o mocks/mock_image.go

// ImageHandler defines API to manipulate images
type ImageHandler interface {
	List(all bool) ([]*abstract.Image, fail.Error)
	Select(osfilter string) (*abstract.Image, fail.Error)
	Filter(osfilter string) ([]abstract.Image, fail.Error)
}

// FIXME: ROBUSTNESS All functions MUST propagate context

// imageHandler image service
type imageHandler struct {
	job backend.Job
}

// NewImageHandler creates a host service
func NewImageHandler(job backend.Job) ImageHandler {
	return &imageHandler{job: job}
}

// List returns the image list
func (handler *imageHandler) List(all bool) (images []*abstract.Image, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}

	return handler.job.Service().ListImages(handler.job.Context(), all)
}

// Select selects the image that best fits osname
func (handler *imageHandler) Select(osname string) (image *abstract.Image, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	return nil, fail.NotImplementedError("ImageHandler.Select() not yet implemented") // FIXME: Technical debt
}

// Filter filters the images that do not fit osname
func (handler *imageHandler) Filter(osname string) (image []abstract.Image, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	return nil, fail.NotImplementedError("ImageHandler.Filter() not yet implemented") // FIXME: Technical debt
}
