package system

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
