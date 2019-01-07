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

package ovh

import (
	"strings"

	filters "github.com/CS-SI/SafeScale/iaas/filters/templates"
	"github.com/CS-SI/SafeScale/iaas/model"
	"github.com/CS-SI/SafeScale/iaas/provider/api"
)

// GetTemplate overload OpenStack GetTemplate method to add GPU configuration
func (p *Ovh) GetTemplate(id string) (*model.HostTemplate, error) {
	tpl, err := p.stack.GetTemplate(id)
	if tpl != nil {
		addGPUCfg(tpl)
	}
	return tpl, err
}

func addGPUCfg(tpl *model.HostTemplate) {
	if cfg, ok := gpuMap[tpl.Name]; ok {
		tpl.GPUNumber = cfg.GPUNumber
		tpl.GPUType = cfg.GPUType
	}
}

// ListTemplates overload OpenStack ListTemplate method to filter wind and flex instance and add GPU configuration
func (client *Client) ListTemplates(all bool) ([]api.HostTemplate, error) {
	allTemplates, err := client.stack.ListTemplates()
	if err != nil {
		return nil, err
	}
	if all {
		return allTemplates, nil
	}

	filter := filters.NewFilter(isWindowsTemplate).Not().And(filters.NewFilter(isFlexTemplate).Not())
	return filters.FilterTemplates(allTemplates, filter), nil
}

func isWindowsTemplate(t api.HostTemplate) bool {
	return strings.HasPrefix(strings.ToLower(t.Name), "win-")
}
func isFlexTemplate(t api.HostTemplate) bool {
	return strings.HasSuffix(strings.ToLower(t.Name), "flex")
}
