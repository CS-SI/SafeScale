package commands

import (
	"bytes"
	"fmt"
	"text/template"

	rice "github.com/GeertJohan/go.rice"
	"github.com/SafeScale/providers"
)

// Return the script (embeded in a rice-box) with placeholders replaced by the values given in data
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

// Execute the given script (embeded in a rice-box) wit the given data on the VM identified by vmid
func exec(script string, data interface{}, vmid string, provider *providers.Service) error {
	scriptCmd, err := getBoxContent(script, data)
	if err != nil {
		// TODO Use more explicit error
		return err
	}
	// retrieve ssh config to perform some commands
	ssh, err := provider.GetSSHConfig(vmid)
	if err != nil {
		// TODO Use more explicit error
		return err
	}

	cmd, err := ssh.SudoCommand(scriptCmd)
	if err != nil {
		// TODO Use more explicit error
		return err
	}
	_, err = cmd.Output()
	return err
}
