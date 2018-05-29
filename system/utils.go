package system
/*
* Copyright 2015-2018, CS Systemes d'Information, http://www.c-s.fr
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

import (
	"bytes"
	"text/template"

	"github.com/GeertJohan/go.rice"
)

//go:generate rice embed-go

//commonToolsContent contains the content of the script common_tools, that will be injected inside scripts through parameter {{.CommonTools}}
var commonToolsContent string

//RealizeCommonTools generates the content of
func RealizeCommonTools() (string, error) {
	if commonToolsContent == "" {
		box, err := rice.FindBox("../system/scripts")
		if err != nil {
			return "", err
		}

		// get file contents as string
		tmplContent, err := box.String("common_tools.sh")
		if err != nil {
			return "", err
		}
		// Prepare the template for execution
		tmplPrepared, err := template.New("common_tools").Parse(tmplContent)
		if err != nil {
			return "", err
		}

		var buffer bytes.Buffer
		if err := tmplPrepared.Execute(&buffer, map[string]interface{}{}); err != nil {
			// TODO Use more explicit error
			return "", err
		}
		commonToolsContent = buffer.String()
	}
	return commonToolsContent, nil
}
