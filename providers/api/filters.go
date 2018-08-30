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

package api

//TemplateFilter is a filter for template. It returns true if the template is filtered (not accepted)
type TemplateFilter func(t HostTemplate) bool

//AnyFilter returns true if the given template is filtered by any filter
func AnyFilter(t HostTemplate, filters []TemplateFilter) bool {
	for _, f := range filters {
		if f(t) {
			return true
		}
	}
	return false
}

// func Not(filter TemplateFilter) TemplateFilter {
// 	return func(t HostTemplate) bool {
// 		return !filter(t)
// 	}
// }

// func AcceptAll(t HostTemplate) bool {
// 	return true
// }

//ImageFilter ...
type ImageFilter func(in Image) bool

//Not ...
func NotFilter(f ImageFilter) ImageFilter {
	return func(in Image) bool {
		return !f(in)
	}
}

//Or ..
func OrFilter(filters []ImageFilter) ImageFilter {
	return func(in Image) bool {
		for _, f := range filters {
			if f(in) {
				return true
			}
		}
		return false
	}
}

//And ...
func AndFilter(filters []ImageFilter) ImageFilter {
	return func(in Image) bool {
		for _, f := range filters {
			if !f(in) {
				return false
			}
		}
		return true
	}
}

//FilterImages ...
func FilterImages(images []Image, f ImageFilter) []Image {
	res := make([]Image, 0)
	for _, img := range images {
		if f(img) {
			res = append(res, img)
		}
	}
	return res
}
