/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

package ovhtf

import (
	"context"
	"regexp"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// InspectTemplate overload OpenStack GetTemplate method to add GPU configuration
func (p *provider) InspectTemplate(ctx context.Context, id string) (*abstract.HostTemplate, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}

	return nil, fail.NotImplementedError()

	/*
		tpl, xerr := p.Stack.InspectTemplate(ctx, id)
		if xerr != nil {
			return nil, xerr
		}

		addGPUCfg(tpl)
		return tpl, nil
	*/
}

func addGPUCfg(tpl *abstract.HostTemplate) {
	if cfg, ok := gpuMap[tpl.Name]; ok {
		tpl.GPUNumber = cfg.GPUNumber
		tpl.GPUType = cfg.GPUType
	}
}

// ListTemplates overload OpenStack ListTemplate method to filter wind and flex instance and add GPU configuration
func (p *provider) ListTemplates(ctx context.Context, all bool) ([]*abstract.HostTemplate, fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}

	return nil, fail.NotImplementedError()

	/*
		allTemplates, xerr := p.Stack.(stacks.ReservedForProviderUse).ListTemplates(ctx, false)
		if xerr != nil {
			return nil, xerr
		}

		if !all {
			// flavor["osType"].(string) == "linux" ?
			filter := filters.NewFilter(isWindowsTemplate).Not().And(filters.NewFilter(isFlexTemplate).Not())
			allTemplates = filters.FilterTemplates(allTemplates, filter)
		}

		// check flavor availability through OVH-API
		authOpts, err := p.GetAuthenticationOptions(ctx)
		if err != nil {
			logrus.WithContext(context.Background()).Warnf("failed to get Authentication options, flavors availability will not be checked: %v", err)
			return allTemplates, nil
		}
		service := authOpts.GetString("TenantID")
		region := authOpts.GetString("Region")

		var listAvailableTemplates []*abstract.HostTemplate
		restURL := fmt.Sprintf("/cloud/project/%s/flavor?region=%s", service, region)
		flavors, xerr := p.requestOVHAPI(ctx, restURL, "GET")
		if xerr != nil {
			logrus.WithContext(context.Background()).Warnf("Unable to request OVH API, flavors availability will not be checked: %v", xerr)
			listAvailableTemplates = allTemplates
		} else {
			flavorMap := map[string]map[string]interface{}{}
			for _, flavor := range flavors.([]interface{}) {
				// Removal of all the unavailable templates
				if flavmap, ok := flavor.(map[string]interface{}); ok {
					if val, ok := flavmap["available"].(bool); ok {
						if val {
							if aflav, ok := flavmap["id"]; ok {
								if key, ok := aflav.(string); ok {
									flavorMap[key] = flavmap
								}
							}
						}
					}
				}
			}

			for _, template := range allTemplates {
				if _, ok := flavorMap[template.ID]; ok {
					// update incomplete disk size of some templates
					if strings.HasPrefix(template.Name, "i1-") {
						template.DiskSize = 2000000
					} else {
						switch template.Name {
						case "t1-180", "t2-180":
							template.DiskSize = 2000000
						default:
						}
					}

					listAvailableTemplates = append(listAvailableTemplates, template)
				} else {
					logrus.WithContext(context.Background()).WithContext(ctx).Warnf("Flavor %s@%s is not available at the moment, ignored", template.Name, template.ID)
				}
			}
		}

		// update incomplete disk size of some templates
		for k, template := range listAvailableTemplates {
			if strings.HasPrefix(template.Name, "i1-") {
				listAvailableTemplates[k].DiskSize += 2000
			} else {
				switch template.Name {
				case "t1-180", "t2-180":
					listAvailableTemplates[k].DiskSize += 2000
				default:
				}
			}
		}

		return listAvailableTemplates, nil
	*/
}

func isWindowsTemplate(t *abstract.HostTemplate) bool {
	return strings.HasPrefix(strings.ToLower(t.Name), "win-")
}

func isFlexTemplate(t *abstract.HostTemplate) bool {
	return strings.HasSuffix(strings.ToLower(t.Name), "flex")
}

// GetRegexpsOfTemplatesWithGPU returns a slice of regexps corresponding to templates with GPU
func (p provider) GetRegexpsOfTemplatesWithGPU() ([]*regexp.Regexp, fail.Error) {
	var emptySlice []*regexp.Regexp
	if valid.IsNil(p) {
		return emptySlice, fail.InvalidInstanceError()
	}

	var (
		templatesWithGPU = []string{
			"t1-.*",
			"g2-.*",
			"g3-.*",
		}
		out []*regexp.Regexp
	)
	for _, v := range templatesWithGPU {
		re, err := regexp.Compile(v)
		if err != nil {
			return emptySlice, fail.ConvertError(err)
		}
		out = append(out, re)
	}

	return out, nil
}
