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

package template

import (
	txttmpl "text/template"

	sprig "github.com/Masterminds/sprig/v3"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// Parse returns a text template with default funcs declared
func Parse(title, content string) (*txttmpl.Template, fail.Error) {
	if title == "" {
		return nil, fail.InvalidParameterError("title", "cannot be empty string")
	}
	if content == "" {
		return nil, fail.InvalidParameterError("content", "cannot be empty string")
	}
	r, err := txttmpl.New(title).Funcs(sprig.TxtFuncMap()).Parse(content)
	if err != nil {
		return nil, fail.ConvertError(err)
	}
	return r, nil
}
