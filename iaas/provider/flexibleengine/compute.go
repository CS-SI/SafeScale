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
package flexibleengine

import (
	"strings"

	"github.com/CS-SI/SafeScale/iaas/model"
)

func addGPUCfg(tpl *resource.HostTemplate) {
	if cfg, ok := gpuMap[tpl.Name]; ok {
		tpl.GPUNumber = cfg.GPUNumber
		tpl.GPUType = cfg.GPUType
	}
}

// GetTemplate returns the Template referenced by id
func (p *FlexibleEngine) GetTemplate(id string) (*model.HostTemplate, error) {
	tpl, err := p.stack.GetTemplate(id)
	if tpl != nil {
		addGPUCfg(tpl)
	}
	return tpl, err
}

// ListTemplates lists available host templates
// Host templates are sorted using Dominant Resource Fairness Algorithm
func (p *FlexibleEngine) ListTemplates() ([]model.HostTemplate, error) {
	allTemplates, err := p.stack.ListTemplates()
	if err != nil {
		return nil, err
	}
	var tpls []resource.HostTemplate
	for _, tpl := range allTemplates {
		addGPUCfg(&tpl)
		tpls = append(tpls, tpl)
	}

	return tpls, nil
}

func isWindowsImage(image model.Image) bool {
	return strings.Contains(strings.ToLower(image.Name), "windows")
}

func isBMSImage(image model.Image) bool {
	return strings.HasPrefix(strings.ToUpper(image.Name), "OBS-BMS") ||
		strings.HasPrefix(strings.ToUpper(image.Name), "OBS_BMS")
}

// ListImages lists available OS images
func (p *FlexibleEngine) ListImages(all) ([]model.Image, error) {
	images, err := p.stack.ListImages()
	if err != nil {
		return nil, err
	}
	if all {
		return images, nil
	}

	imageFilter := filters.NewFilter(isWindowsImage).Not().And(filters.NewFilter(isBMSImage).Not())
	return filters.FilterImages(images, imageFilter), nil
}
