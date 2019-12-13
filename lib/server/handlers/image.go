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
	"fmt"

	"github.com/CS-SI/SafeScale/lib/server"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

//go:generate mockgen -destination=../mocks/mock_imageapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers ImageAPI

// TODO At service level, ve need to log before returning, because it's the last chance to track the real issue in server side

// ImageAPI defines API to manipulate images
type ImageAPI interface {
	List(all bool) ([]resources.Image, error)
	Select(osfilter string) (*resources.Image, error)
	Filter(osfilter string) ([]resources.Image, error)
}

// FIXME ROBUSTNESS All functions MUST propagate context

// ImageHandler image service
type ImageHandler struct {
	job server.Job
}

// NewImageHandler creates an host service
func NewImageHandler(job server.Job) ImageAPI {
	return &ImageHandler{job: job}
}

// List returns the image list
func (handler *ImageHandler) List(all bool) (images []resources.Image, err error) { // FIXME Unused ctx
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("(%v)", all), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	return handler.job.Service().ListImages(all)
}

// Select selects the image that best fits osname
func (handler *ImageHandler) Select(osname string) (image *resources.Image, err error) { // FIXME Unused ctx
	return nil, nil
}

// Filter filters the images that do not fit osname
func (handler *ImageHandler) Filter(osname string) (image []resources.Image, err error) { // FIXME Unused ctx
	return nil, nil
}
