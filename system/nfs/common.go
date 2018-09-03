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

package nfs

import (
	"bytes"
	"fmt"
	"os/exec"
	"syscall"
	"text/template"

	"github.com/CS-SI/SafeScale/system"
	"github.com/GeertJohan/go.rice"
)

//go:generate rice embed-go

//templateProvider is the instance of TemplateProvider used by package nfs
var tmplBox *rice.Box

//getTemplateProvider returns the instance of TemplateProvider
func getTemplateBox() (*rice.Box, error) {
	if tmplBox == nil {
		var err error
		tmplBox, err = rice.FindBox("../nfs/scripts")
		if err != nil {
			return nil, err
		}
	}
	return tmplBox, nil
}

//executeScript executes a script template with parameters in data map
// Returns retcode, stdout, stderr, error
// If error == nil && retcode != 0, the script ran but failed.
func executeScript(sshconfig system.SSHConfig, name string, data map[string]interface{}) (int, string, string, error) {
	bashLibrary, err := system.GetBashLibrary()
	if err != nil {
		return 255, "", "", err
	}
	data["reserved_BashLibrary"] = bashLibrary

	tmplBox, err := getTemplateBox()

	// get file content as string
	tmplContent, err := tmplBox.String(name)
	if err != nil {
		return 255, "", "", err
	}

	// Prepare the template for execution
	tmplPrepared, err := template.New(name).Parse(tmplContent)
	if err != nil {
		return 255, "", "", err
	}

	var buffer bytes.Buffer
	if err := tmplPrepared.Execute(&buffer, data); err != nil {
		return 255, "", "", fmt.Errorf("failed to execute template: %s", err.Error())
	}
	tmplResult := buffer.String()
	sshCmd, err := sshconfig.SudoCommand(tmplResult)
	if err != nil {
		return 255, "", "", err
	}

	cmdResult, err := sshCmd.Output()
	retcode := 0
	stdout := string(cmdResult)
	stderr := ""
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			if status, ok := ee.Sys().(syscall.WaitStatus); ok {
				retcode = status.ExitStatus()
			}
			stderr = string(ee.Stderr)
		} else {
			return 255, "", "", fmt.Errorf("failed to execute script '%s': %s", name, err.Error())
		}
	}
	return retcode, stdout, stderr, nil
}

func handleExecuteScriptReturn(retcode int, stdout string, stderr string, err error, msg string) error {
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fmt.Errorf("%s: %s", msg, stderr)
	}
	return nil
}
