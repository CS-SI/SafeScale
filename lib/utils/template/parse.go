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

package template

import (
	txttmpl "text/template"

	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// Parse returns a text template with default funcs declared
func Parse(title, content string, funcMap map[string]interface{}) (*txttmpl.Template, error) {
	if title == "" {
		return nil, scerr.InvalidParameterError("title", "cannot be empty string")
	}
	if content == "" {
		return nil, scerr.InvalidParameterError("content", "cannot be empty string")
	}
	return txttmpl.New(title).Funcs(MergeFuncs(funcMap, false)).Parse(content)
}
