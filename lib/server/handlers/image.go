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

package handlers

import (
	"fmt"

	"github.com/CS-SI/SafeScale/lib/server"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

//go:generate mockgen -destination=../mocks/mock_imageapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers ImageAPI

// TODO At service level, ve need to log before returning, because it's the last chance to track the real issue in server side

// ImageAPI defines API to manipulate images
type ImageHandler interface {
	List(all bool) ([]abstract.Image, error)
	Select(osfilter string) (*abstract.Image, error)
	Filter(osfilter string) ([]abstract.Image, error)
}

// FIXME ROBUSTNESS All functions MUST propagate context

// imageHandler image service
type imageHandler struct {
	job server.Job
}

// NewImageHandler creates an host service
func NewImageHandler(job server.Job) ImageHandler {
	return &ImageHandler{job: job}
}

// List returns the image list
func (handler *imageHandler) List(all bool) (images []abstract.Image, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, scerr.InvalidInstanceContentError("handler.job", "cannot be nil"
	}

	tracer := concurrency.NewTracer(handler.job.Task(), fmt.Sprintf("(%v)", all), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	return handler.job.Service().ListImages(all)
}

// Select selects the image that best fits osname
func (handler *imageHandler) Select(osname string) (image *abstract.Image, err error) {
	return nil, scerr.NotImplementedError("ImageHandler.Select() not yet implemented")
}

// Filter filters the images that do not fit osname
func (handler *imageHandler) Filter(osname string) (image []abstract.Image, err error) {
	return nil, scerr.NotImplementedError("ImageHandler.Filter() not yet implemented")
}
