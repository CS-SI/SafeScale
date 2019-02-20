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

package handlers

import (
	"bytes"
	"context"
	"text/template"

	"github.com/CS-SI/SafeScale/iaas"
	rice "github.com/GeertJohan/go.rice"
)

//go:generate rice embed-go

// Return the script (embeded in a rice-box) with placeholders replaced by the values given in data
func getBoxContent(script string, data interface{}) (string, error) {

	box, err := rice.FindBox("broker_scripts")
	if err != nil {
		return "", infraErrf(err, "Unable to find script broker_scripts")
	}
	scriptContent, err := box.String(script)
	if err != nil {
		return "", infraErrf(err, "Unable to recover script content")
	}
	tpl, err := template.New("TemplateName").Parse(scriptContent)
	if err != nil {
		return "", infraErrf(err, "Unable to parse script content")
	}

	var buffer bytes.Buffer
	if err = tpl.Execute(&buffer, data); err != nil {
		return "", infraErrf(err, "Error in script execution")
	}

	tplcmd := buffer.String()
	// fmt.Println(tplcmd)
	return tplcmd, nil
}

// Execute the given script (embeded in a rice-box) with the given data on the host identified by hostid
func exec(ctx context.Context, script string, data interface{}, hostid string, provider *providers.Service) error {
func exec(script string, data interface{}, hostid string, svc *iaas.Service) error {
	scriptCmd, err := getBoxContent(script, data)
	if err != nil {
		return infraErrf(err, "Unable to get the script string")
	}
	// retrieve ssh config to perform some commands
	sshHandler := NewSSHHandler(svc)
	ssh, err := sshHandler.GetConfig(ctx, hostid)
	if err != nil {
		return infraErrf(err, "Unable to fetch the SSHConfig from the host")
	}

	cmd, err := ssh.SudoCommand(scriptCmd)
	if err != nil {
		return infraErrf(err, "Unable to convert the script string in a SSHCommand struct")
	}
	_, err = cmd.Output()

	if err != nil {
		return infraErrf(err, "Unable to execute the command as a root user on the host")
	}
	return nil
}
