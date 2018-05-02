package commands

import (
	"bytes"
	"fmt"
	"text/template"

	rice "github.com/GeertJohan/go.rice"
)

func getBoxContent(script string, data interface{}) (string, error) {

	box, err := rice.FindBox("broker_scripts")
	if err != nil {
		// TODO Use more explicit error
		return "", err
	}
	scriptContent, err := box.String(script)
	if err != nil {
		// TODO Use more explicit error
		return "", err
	}
	tpl, err := template.New("TemplateName").Parse(scriptContent)
	if err != nil {
		// TODO Use more explicit error
		return "", err
	}

	var buffer bytes.Buffer
	if err = tpl.Execute(&buffer, data); err != nil {
		// TODO Use more explicit error
		return "", err
	}

	tplcmd := buffer.String()
	fmt.Println(tplcmd)
	return tplcmd, nil
}
