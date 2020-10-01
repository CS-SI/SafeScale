/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"fmt"

	"github.com/CS-SI/SafeScale/lib/utils/debug"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

//go:generate mockgen -destination=../mocks/mock_templateapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers TemplateAPI

// TODO: At service level, ve need to log before returning, because it's the last chance to track the real issue in server side

// TemplateAPI defines API to manipulate hosts
type TemplateAPI interface {
	List(ctx context.Context, all bool) ([]abstract.HostTemplate, error)
}

// TemplateHandler template service
type TemplateHandler struct {
	service iaas.Service
}

// NewTemplateHandler creates a template service
func NewTemplateHandler(svc iaas.Service) TemplateAPI {
	return &TemplateHandler{
		service: svc,
	}
}

// List returns the template list
func (handler *TemplateHandler) List(ctx context.Context, all bool) (tlist []abstract.HostTemplate, err error) {
	tracer := debug.NewTracer(nil, fmt.Sprintf("(%v)", all), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	tlist, err = handler.service.ListTemplates(all)
	return tlist, err
}
