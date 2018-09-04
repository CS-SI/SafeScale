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

package components

import (
	"bytes"
	"fmt"
	"text/template"

	rice "github.com/GeertJohan/go.rice"

	"github.com/CS-SI/SafeScale/deploy/install"

	pb "github.com/CS-SI/SafeScale/broker"
)

//go:generate rice embed-go

var (
	// templateBox is the rice box to use in this package
	templateBox *rice.Box

	//installCommonsContent contains the script to install/configure common components
	installCommonsContent *string

	funcMap = template.FuncMap{
		// The name "inc" is what the function will be called in the template text.
		"inc": func(i int) int {
			return i + 1
		},
	}
)

// getTemplateBox
func getTemplateBox() (*rice.Box, error) {
	if templateBox == nil {
		b, err := rice.FindBox("../../cluster/components/scripts")
		if err != nil {
			return nil, err
		}
		templateBox = b
	}
	return templateBox, nil
}

// UploadBuildScript creates the string corresponding to script
// used to prepare Docker image to be used by a cluster
func UploadBuildScript(host *pb.Host, component string, data map[string]interface{}) (string, error) {
	// find the rice.Box
	b, err := getTemplateBox()
	if err != nil {
		return "", err
	}
	scriptName := "docker_image_create_" + component + ".sh"
	remotePath := "/var/tmp/" + scriptName
	// get file contents as string
	tmplString, err := b.String(scriptName)
	if err != nil {
		return "", fmt.Errorf("error loading component '%s' template: %s", component, err.Error())
	}
	// Parse the template
	tmplPrepared, err := template.New(scriptName).Funcs(funcMap).Parse(tmplString)
	if err != nil {
		return "", fmt.Errorf("error parsing component '%s' template: %s", component, err.Error())
	}
	// realize the template
	dataBuffer := bytes.NewBufferString("")
	err = tmplPrepared.Execute(dataBuffer, data)
	if err != nil {
		return "", fmt.Errorf("error realizing component '%s' template: %s", scriptName, err.Error())
	}
	err = install.UploadStringToRemoteFile(dataBuffer.String(), host, remotePath)
	if err != nil {
		return "", err
	}
	return remotePath, nil
}
