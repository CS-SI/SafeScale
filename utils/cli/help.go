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

package cli

import (
	"bytes"
	"fmt"
	"text/template"
)

var helpTemplate = `
{{- if .Title }}{{ .Title }}{{- end}}
{{ .Usage }}
{{ if .Commands }}
Commands:
{{- .Commands }}
{{ end }}

{{- range .Options }}
{{ . }}

{{- end }}

{{- if .Description }}
  {{ .Description }}
{{- end }}

{{- if .Examples }}
  {{ .Examples }}
{{- end }}

{{- if .Footer }}
  {{ .Footer }}
{{- end }}`

// HelpContent stores content to build help message
type HelpContent struct {
	Template    string
	Title       string
	Usage       string
	Commands    string
	Options     []string
	Description string
	Examples    string
	Footer      string
}

// Assemble put pieces alltogether to create help message
func (hc *HelpContent) Assemble(progName string) string {
	var err error
	var tmpl *template.Template

	// First pass to parse template
	if hc.Template == "" {
		tmpl, err = template.New("help_pass_1").Parse(helpTemplate)
	} else {
		tmpl, err = template.New("help_pass_1").Parse(hc.Template)

	}
	if err != nil {
		return fmt.Sprintf("error parsing help template: %s", err.Error())
	}
	if RebrandPrefix != "" {
		progName = RebrandPrefix + progName
	}
	dataBuffer := bytes.NewBufferString("")
	err = tmpl.Execute(dataBuffer, map[string]interface{}{
		"ProgName":    progName,
		"Title":       hc.Title,
		"Usage":       hc.Usage,
		"Commands":    hc.Commands,
		"Options":     hc.Options,
		"Description": hc.Description,
		"Examples":    hc.Examples,
		"Footer":      hc.Footer,
	})
	if err != nil {
		return fmt.Sprintf("error realizing help template: %s", err.Error())
	}

	// Second pass to parse ProgramName in the result (only allowed variable in help contents)
	tmpl, err = template.New("help_pass_2").Parse(dataBuffer.String())
	if err != nil {
		return fmt.Sprintf("error parsing help template: %s", err.Error())
	}
	dataBuffer = bytes.NewBufferString("")
	err = tmpl.Execute(dataBuffer, map[string]interface{}{
		"ProgName": progName,
	})
	if err != nil {
		return fmt.Sprintf("error realizing help template: %s", err.Error())
	}
	return dataBuffer.String()
}
