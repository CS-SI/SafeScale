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

type IImageFilter interface {
	Filter(img Image) bool
	Not() *IImageFilter
	And(imf *IImageFilter) *IImageFilter
	Or(imf *IImageFilter) *IImageFilter
}

//Filter ...
type Filter struct {
	filter Predicate
}

func NewFilter(predicate Predicate) *Filter {
	return &Filter{filter: predicate}
}

//Predicate ...
type Predicate func(img Image) bool

//Not ...
func (f *Filter) Not() *Filter {
	oldFilter := f.filter
	f.filter = func(in Image) bool {
		return !oldFilter(in)
	}
	return f
}

//And ...
func (f *Filter) And(other *Filter) *Filter {
	oldFilter := f.filter
	f.filter = func(in Image) bool {
		return oldFilter(in) && (*other).filter(in)
	}
	return f
}

//Or ...
func (f *Filter) Or(other *Filter) *Filter {
	oldFilter := f.filter
	f.filter = func(in Image) bool {
		return oldFilter(in) || (*other).filter(in)
	}
	return f
}

//NotFilter ...
func NotFilter(f Predicate) Predicate {
	return func(in Image) bool {
		return !f(in)
	}
}

//OrFilter ..
func OrFilter(filters ...Predicate) Predicate {
	return func(in Image) bool {
		for _, f := range filters {
			if f(in) {
				return true
			}
		}
		return false
	}
}

//AndFilter ...
func AndFilter(filters ...Predicate) Predicate {
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
func FilterImages(images []Image, f *Filter) []Image {
	res := make([]Image, 0)
	for _, img := range images {

		if f.filter(img) {
			res = append(res, img)
		}
	}
	return res
}

//FilterImages ...
// func FilterSAE(items []Filterable, f *Filter) []Filterable {
// 	res := make([]Filterable, 0, len(items))
// 	for _, item := range items {
// 		if (*f).filter(item) {
// 			res = append(res, item)
// 		}
// 	}
// 	return res
// }

// //FilterImages ...
// func FilterImages(images []Image, f ImagePredicate) []Image {
// 	res := make([]Image, 0)
// 	for _, img := range images {
// 		if f(img) {
// 			res = append(res, img)
// 		}
// 	}
// 	return res
// }
