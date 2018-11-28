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

package templates

import (
	"github.com/CS-SI/SafeScale/providers/model"
)

// Filter ...
type Filter struct {
	filter Predicate
}

// Predicate ...
type Predicate func(model.HostTemplate) bool

// NewFilter creates a new filter with the given predicate
func NewFilter(predicate Predicate) *Filter {
	return &Filter{filter: predicate}
}

// Not ...
func (f *Filter) Not() *Filter {
	oldFilter := f.filter
	f.filter = func(in model.HostTemplate) bool {
		return !oldFilter(in)
	}
	return f
}

// And ...
func (f *Filter) And(other *Filter) *Filter {
	oldFilter := f.filter
	f.filter = func(in model.HostTemplate) bool {
		return oldFilter(in) && (*other).filter(in)
	}
	return f
}

// Or ...
func (f *Filter) Or(other *Filter) *Filter {
	oldFilter := f.filter
	f.filter = func(in model.HostTemplate) bool {
		return oldFilter(in) || (*other).filter(in)
	}
	return f
}

// Not ...
func Not(f Predicate) Predicate {
	return func(in model.HostTemplate) bool {
		return !f(in)
	}
}

// OrFilter ..
func OrFilter(filters ...Predicate) Predicate {
	return func(in model.HostTemplate) bool {
		for _, f := range filters {
			if f(in) {
				return true
			}
		}
		return false
	}
}

// AndFilter ...
func AndFilter(filters ...Predicate) Predicate {
	return func(in model.HostTemplate) bool {
		for _, f := range filters {
			if !f(in) {
				return false
			}
		}
		return true
	}
}

// FilterTemplates ...
func FilterTemplates(templates []model.HostTemplate, f *Filter) []model.HostTemplate {
	res := make([]model.HostTemplate, 0)
	for _, template := range templates {

		if f.filter(template) {
			res = append(res, template)
		}
	}
	return res
}
