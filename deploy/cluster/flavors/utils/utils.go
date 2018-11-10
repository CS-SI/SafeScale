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

package utils

import (
	"bytes"
	"fmt"
	txttmpl "text/template"
	"time"

	rice "github.com/GeertJohan/go.rice"

	brokerclient "github.com/CS-SI/SafeScale/broker/client"
	"github.com/CS-SI/SafeScale/deploy/install"
	"github.com/CS-SI/SafeScale/system"
	"github.com/CS-SI/SafeScale/utils/template"
)

const (
	tempFolder = "/var/tmp/"
)

var (
	// systemTemplateBox ...
	systemTemplateBox *rice.Box
	// bashLibraryContent contains the script containing bash library
	bashLibraryContent *string
)

// ExecuteScript executes the script template with the parameters on tarGetHost
func ExecuteScript(
	box *rice.Box, funcMap map[string]interface{}, tmplName string, data map[string]interface{},
	hostID string,
) (int, string, string, error) {
	// Configures reserved_BashLibrary template var
	bashLibrary, err := system.GetBashLibrary()
	if err != nil {
		return 0, "", "", err
	}
	data["reserved_BashLibrary"] = bashLibrary

	path, err := UploadTemplateToFile(box, funcMap, tmplName, data, hostID, tmplName)
	if err != nil {
		return 0, "", "", err
	}
	var cmd string
	//if debug
	if true {
		cmd = fmt.Sprintf("sudo bash %s", path)
	} else {
		cmd = fmt.Sprintf("sudo bash %s; rc=$?; rm %s; exit $rc", path, path)
	}
	return brokerclient.New().Ssh.Run(hostID, cmd, brokerclient.DefaultConnectionTimeout, time.Duration(20)*time.Minute)
}

// UploadTemplateToFile uploads a template named 'tmplName' coming from rice 'box' in a file to a remote host
func UploadTemplateToFile(
	box *rice.Box, funcMap map[string]interface{}, tmplName string, data map[string]interface{},
	hostID string, fileName string,
) (string, error) {

	if box == nil {
		panic("box is nil!")
	}
	broker := brokerclient.New()
	host, err := broker.Host.Inspect(hostID, brokerclient.DefaultExecutionTimeout)
	if err != err {
		return "", fmt.Errorf("failed to get host information: %s", err)
	}

	tmplString, err := box.String(tmplName)
	if err != nil {
		return "", fmt.Errorf("failed to load template: %s", err.Error())
	}
	tmplCmd, err := txttmpl.New(fileName).Funcs(template.MergeFuncs(funcMap, false)).Parse(tmplString)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %s", err.Error())
	}
	dataBuffer := bytes.NewBufferString("")
	err = tmplCmd.Execute(dataBuffer, data)
	if err != nil {
		return "", fmt.Errorf("failed to realize template: %s", err.Error())
	}
	cmd := dataBuffer.String()
	remotePath := tempFolder + fileName

	err = install.UploadStringToRemoteFile(cmd, host, remotePath, "", "", "")
	if err != nil {
		return "", err
	}
	return remotePath, nil
}
