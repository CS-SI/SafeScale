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

package handlers

import (
	"context"

	"github.com/CS-SI/SafeScale/iaas"
	"github.com/CS-SI/SafeScale/iaas/resources"
)

//go:generate mockgen -destination=../mocks/mock_templateapi.go -package=mocks github.com/CS-SI/SafeScale/broker/server/handlers TemplateAPI

// TODO At service level, ve need to log before returning, because it's the last chance to track the real issue in server side

//TemplateAPI defines API to manipulate hosts
type TemplateAPI interface {
	List(all bool) ([]resources.HostTemplate, error)
	List(ctx context.Context, all bool) ([]model.HostTemplate, error)
}

// TemplateHandler template service
type TemplateHandler struct {
	service *iaas.Service
}

// NewTemplateHandler creates a template service
func NewTemplateHandler(svc *iaas.Service) TemplateAPI {
	return &TemplateHandler{
		service: svc,
	}
}

// List returns the template list
func (handler *TemplateHandler) List(all bool) ([]resources.HostTemplate, error) {
func (svc *TemplateHandler) List(ctx context.Context, all bool) ([]model.HostTemplate, error) {
	tlist, err := handler.service.ListTemplates(all)
	tlist, err := svc.provider.ListTemplates(all)
	return tlist, infraErr(err)
}
