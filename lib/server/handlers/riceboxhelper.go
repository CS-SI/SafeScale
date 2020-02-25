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

package handlers

import (
	"bytes"
	"text/template"

	rice "github.com/GeertJohan/go.rice"

	"github.com/CS-SI/SafeScale/lib/server"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

//go:generate rice embed-go

// Return the script (embeded in a rice-box) with placeholders replaced by the values given in data
func getBoxContent(script string, data interface{}) (tplcmd string, err error) {
	defer scerr.OnExitLogError(concurrency.NewTracer(nil, true, "").TraceMessage(""), &err)()

	box, err := rice.FindBox("../handlers/scripts")
	if err != nil {
		return "", err
	}
	scriptContent, err := box.String(script)
	if err != nil {
		return "", err
	}
	tpl, err := template.New("TemplateName").Parse(scriptContent)
	if err != nil {
		return "", err
	}

	var buffer bytes.Buffer
	if err = tpl.Execute(&buffer, data); err != nil {
		return "", err
	}

	tplcmd = buffer.String()
	// fmt.Println(tplcmd)
	return tplcmd, nil
}

// Execute the given script (embedded in a rice-box) with the given data on the host identified by hostid
func exec(job server.Job, script string, data interface{}, hostid string, svc iaas.Service) error {
	scriptCmd, err := getBoxContent(script, data)
	if err != nil {
		return err
	}
	// retrieve ssh config to perform some commands
	sshHandler := NewSSHHandler(job)
	ssh, err := sshHandler.GetConfig((hostid))
	if err != nil {
		return err
	}

	_, err = ssh.SudoCommand(job.SafeGetTask(), scriptCmd)
	return err
}
