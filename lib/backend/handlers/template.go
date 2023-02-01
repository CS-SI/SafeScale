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

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/backend/handlers.TemplateHandler -o mocks/mock_template.go

// TemplateHandler defines API to manipulate images
type TemplateHandler interface {
	Inspect(string) (*abstract.HostTemplate, fail.Error)
	List(bool) ([]*abstract.HostTemplate, fail.Error)
	Match(abstract.HostSizingRequirements) ([]*abstract.HostTemplate, fail.Error)
}

// templateHandler image service
type templateHandler struct {
	job backend.Job
}

// NewTemplateHandler creates a host service
func NewTemplateHandler(job backend.Job) TemplateHandler {
	return &templateHandler{job: job}
}

// List available templates
func (handler *templateHandler) List(all bool) (_ []*abstract.HostTemplate, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}

	return handler.job.Service().ListTemplates(handler.job.Context(), all)
}

// Match lists templates that match the sizing
func (handler *templateHandler) Match(sizing abstract.HostSizingRequirements) (_ []*abstract.HostTemplate, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}

	return handler.job.Service().ListTemplatesBySizing(handler.job.Context(), sizing, false)
}

// Inspect returns information about a tenant
func (handler *templateHandler) Inspect(ref string) (_ *abstract.HostTemplate, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}

	return handler.job.Service().FindTemplateByName(handler.job.Context(), ref)
}
