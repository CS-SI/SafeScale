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

//go:generate mockgen -destination=../mocks/mock_templateapi.go -package=mocks github.com/CS-SI/SafeScale/broker/server/services TemplateAPI

// TODO At service level, ve need to log before returning, because it's the last chance to track the real issue in server side

//TemplateAPI defines API to manipulate hosts
type TemplateAPI interface {
	List(all bool) ([]model.HostTemplate, error)
}

//NewTemplateService creates a template service
func NewTemplateService(api *providers.Service) TemplateAPI {
	return &TemplateService{
		provider: api,
	}
}

// TemplateService template service
type TemplateService struct {
	provider *providers.Service
}

// List returns the template list
func (srv *TemplateService) List(all bool) ([]model.HostTemplate, error) {
	tlist, err := srv.provider.ListTemplates(all)
	return tlist, infraErr(err)
}
