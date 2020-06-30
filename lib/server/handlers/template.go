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
	"github.com/CS-SI/SafeScale/lib/server"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

//go:generate mockgen -destination=../mocks/mock_templateapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers TemplateHandler

// TODO At service level, ve need to log before returning, because it's the last chance to track the real issue in server side

// TemplateHandler defines API to manipulate hosts
type TemplateHandler interface {
	List(all bool) ([]abstract.HostTemplate, fail.Error)
}

// templateHandler template service
type templateHandler struct {
	job server.Job
}

// NewTemplateHandler creates a template service
// FIXME: what to do if job == nil ?
func NewTemplateHandler(job server.Job) TemplateHandler {
	return &templateHandler{job: job}
}

// ErrorList returns the template list
func (handler *templateHandler) List(all bool) (tlist []abstract.HostTemplate, xerr fail.Error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}

	tracer := concurrency.NewTracer(handler.job.GetTask(), debug.ShouldTrace("handlers.template"), "(%v)", all).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &xerr)

	return handler.job.GetService().ListTemplates(all)
}
