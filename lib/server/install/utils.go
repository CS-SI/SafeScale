/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package install

import (
	"bytes"
	"fmt"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"strings"
	"text/template"

	// log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/client"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
)

const (
	featureScriptTemplateContent = `#!/bin/bash -x

set -u -o pipefail

print_error() {
    read line file <<<$(caller)
    echo "An error occurred in line $line of file $file:" "{"` + "`" + `sed "${line}q;d" "$file"` + "`" + `"}" >&2
}
trap print_error ERR

set +x
rm -f %s/feature.{{.reserved_Name}}.{{.reserved_Action}}_{{.reserved_Step}}.log
exec 1<&-
exec 2<&-
exec 1<>%s/feature.{{.reserved_Name}}.{{.reserved_Action}}_{{.reserved_Step}}.log
exec 2>&1
set -x

{{ .reserved_BashLibrary }}

{{ .reserved_Content }}
`
)

var (
	featureScriptTemplate *template.Template
)

// parseTargets validates targets on the cluster from the feature specification
// Without error, returns 'master target', 'private node target' and 'public node target'
func parseTargets(specs *viper.Viper) (string, string, string, error) {
	if !specs.IsSet("feature.target.cluster") {
		return "", "", "", fmt.Errorf("feature isn't suitable for a cluster")
	}

	master := strings.ToLower(strings.TrimSpace(specs.GetString("feature.target.cluster.master")))
	switch master {
	case "":
		fallthrough
	case "false":
		fallthrough
	case "no":
		fallthrough
	case "none":
		fallthrough
	case "0":
		master = "0"
	case "any":
		fallthrough
	case "one":
		fallthrough
	case "1":
		master = "1"
	case "all":
		fallthrough
	case "*":
		master = "*"
	default:
		return "", "", "", fmt.Errorf("invalid value '%s' for field 'feature.target.cluster.master'", master)
	}

	privnode := strings.ToLower(strings.TrimSpace(specs.GetString("feature.target.cluster.node.private")))
	switch privnode {
	case "false":
		fallthrough
	case "no":
		fallthrough
	case "none":
		privnode = "0"
	case "any":
		fallthrough
	case "one":
		fallthrough
	case "1":
		privnode = "1"
	case "":
		fallthrough
	case "all":
		fallthrough
	case "*":
		privnode = "*"
	default:
		return "", "", "", fmt.Errorf("invalid value '%s' for field 'feature.target.cluster.node.private'", privnode)
	}

	pubnode := strings.ToLower(strings.TrimSpace(specs.GetString("feature.target.cluster.node.public")))
	switch pubnode {
	case "":
		fallthrough
	case "false":
		fallthrough
	case "no":
		fallthrough
	case "none":
		fallthrough
	case "0":
		pubnode = "0"
	case "any":
		fallthrough
	case "one":
		fallthrough
	case "1":
		pubnode = "1"
	case "all":
		fallthrough
	case "*":
		pubnode = "*"
	default:
		return "", "", "", fmt.Errorf("invalid value '%s' for field 'feature.target.cluster.node.public'", pubnode)
	}

	if master == "0" && privnode == "0" && pubnode == "0" {
		return "", "", "", fmt.Errorf("invalid 'feature.target.cluster': no target designated")
	}
	return master, privnode, pubnode, nil
}

// UploadStringToRemoteFile creates a file 'filename' on remote 'host' with the content 'content'
func UploadStringToRemoteFile(content string, host *pb.Host, filename string, owner, group, rights string) error {
	if content == "" {
		panic("content is empty!")
	}
	if host == nil {
		panic("host is nil!")
	}
	if filename == "" {
		panic("filename is empty!")
	}

	if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
		_ = os.MkdirAll(utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s", host.Name)), 0777)
		partials := strings.Split(filename, "/")
		dumpName := utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s/%s", host.Name, partials[len(partials)-1]))

		err := ioutil.WriteFile(dumpName, []byte(content), 0644)
		if err != nil {
			logrus.Warnf("[TRACE] Forensics error creating %s", dumpName)
		}
	}

	f, err := system.CreateTempFileFromString(content, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %s", err.Error())
	}
	to := fmt.Sprintf("%s:%s", host.Name, filename)
	sshClt := client.New().Ssh
	networkError := false
	retryErr := retry.WhileUnsuccessful(
		func() error {
			retcode, _, _, err := sshClt.Copy(f.Name(), to, utils.GetDefaultDelay(), utils.GetExecutionTimeout()) // FIXME File operations
			if err != nil {
				return err
			}
			if retcode != 0 {
				// If retcode == 1 (general copy error), retry. It may be a temporary network incident
				if retcode == 1 {
					// File may exist on target, try to remote it
					_, _, _, err = sshClt.Run(host.Name, fmt.Sprintf("sudo rm -f %s", filename), utils.GetBigDelay(), utils.GetExecutionTimeout())
					if err == nil {
						return fmt.Errorf("file may exist on remote with inappropriate access rights, deleted it and retrying")
					}
					// If submission of removal of remote file fails, stop the retry and consider this as an unrecoverable network error
					networkError = true
					return nil
				}
				if system.IsSCPRetryable(retcode) {
					err = fmt.Errorf("failed to copy temporary file to '%s' (retcode: %d=%s)", to, retcode, system.SCPErrorString(retcode))
				}
				return nil
			}
			return nil
		},
		utils.GetDefaultDelay(),
		2*utils.GetContextTimeout(),
	)
	_ = os.Remove(f.Name())
	if networkError {
		return fmt.Errorf("an unrecoverable network error has occurred")
	}
	if retryErr != nil {
		switch retryErr.(type) {
		case retry.ErrTimeout:
			return fmt.Errorf("timeout trying to copy temporary file to '%s': %s", to, retryErr.Error())
		}
		return err
	}

	cmd := ""
	if owner != "" {
		cmd += "sudo chown " + owner + " " + filename
	}
	if group != "" {
		if cmd != "" {
			cmd += " && "
		}
		cmd += "sudo chgrp " + group + " " + filename
	}
	if rights != "" {
		if cmd != "" {
			cmd += " && "
		}
		cmd += "sudo chmod " + rights + " " + filename
	}
	retryErr = retry.WhileUnsuccessful(
		func() error {
			var retcode int
			retcode, _, _, err = sshClt.Run(host.Name, cmd, utils.GetDefaultDelay(), utils.GetExecutionTimeout())
			if err != nil {
				return err
			}
			if retcode != 0 {
				err = fmt.Errorf("failed to change rights of file '%s' (retcode=%d)", to, retcode)
				return nil
			}
			return nil
		},
		utils.GetMinDelay(),
		utils.GetContextTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case retry.ErrTimeout:
			return fmt.Errorf("timeout trying to change rights of file '%s' on host '%s': %s", filename, host.Name, err.Error())
		default:
			return fmt.Errorf("failed to change rights of file '%s' on host '%s': %s", filename, host.Name, retryErr.Error())
		}
	}
	return nil
}

// normalizeScript envelops the script with log redirection to /opt/safescale/var/log/feature.<name>.<action>.log
// and ensures BashLibrary are there
func normalizeScript(params map[string]interface{}) (string, error) {
	var err error

	if featureScriptTemplate == nil {
		// parse then execute the template
		tmpl := fmt.Sprintf(featureScriptTemplateContent, srvutils.LogFolder, srvutils.LogFolder)
		featureScriptTemplate, err = template.New("normalize_script").Parse(tmpl)
		if err != nil {
			return "", fmt.Errorf("error parsing bash template: %s", err.Error())
		}
	}

	// Configures BashLibrary template var
	bashLibrary, err := system.GetBashLibrary()
	if err != nil {
		return "", err
	}
	params["reserved_BashLibrary"] = bashLibrary

	dataBuffer := bytes.NewBufferString("")
	err = featureScriptTemplate.Execute(dataBuffer, params)
	if err != nil {
		return "", err
	}

	return dataBuffer.String(), nil
}

// realizeVariables replaces in every variable any template
func realizeVariables(variables Variables) (Variables, error) {
	cloneV := variables.Clone()

	for k, v := range cloneV {
		if variable, ok := v.(string); ok {
			varTemplate, err := template.New("realize_var").Parse(variable)
			if err != nil {
				return nil, fmt.Errorf("error parsing variable '%s': %s", k, err.Error())
			}
			buffer := bytes.NewBufferString("")
			err = varTemplate.Execute(buffer, variables)
			if err != nil {
				return nil, err
			}
			cloneV[k] = buffer.String()
		}
	}

	return cloneV, nil
}

func replaceVariablesInString(text string, v Variables) (string, error) {
	tmpl, err := template.New("text").Parse(text)
	if err != nil {
		return "", fmt.Errorf("failed to parse: %s", err.Error())
	}
	dataBuffer := bytes.NewBufferString("")
	err = tmpl.Execute(dataBuffer, v)
	if err != nil {
		return "", fmt.Errorf("failed to replace variables: %s", err.Error())
	}
	return dataBuffer.String(), nil
}

func findConcernedHosts(list []string, c *Feature) (string, error) {
	// No metadata yet for features, first host is designated concerned host
	if len(list) > 0 {
		return list[0], nil
	}
	return "", fmt.Errorf("no hosts")
	//for _, h := range list {
	//}
}

// determineContext ...
func determineContext(t Target) (hT *HostTarget, cT *ClusterTarget, nT *NodeTarget) {
	hT = nil
	cT = nil
	nT = nil

	var ok bool

	hT, ok = t.(*HostTarget)
	if !ok {
		cT, ok = t.(*ClusterTarget)
		if !ok {
			nT, _ = t.(*NodeTarget)
		}
	}
	return
}

// Check if required parameters defined in specification file have been set in 'v'
func checkParameters(f *Feature, v Variables) error {
	if f.specs.IsSet("feature.parameters") {
		params := f.specs.GetStringSlice("feature.parameters")
		for _, k := range params {
			splitted := strings.Split(k, "=")
			if _, ok := v[splitted[0]]; !ok {
				if len(splitted) == 1 {
					return fmt.Errorf("missing value for parameter '%s'", k)
				}
				v[splitted[0]] = strings.Join(splitted[1:], "=")
			}
		}
	}
	return nil
}

func gatewayFromHost(host *pb.Host) *pb.Host {
	gwID := host.GetGatewayId()
	// If host has no gateway, host is gateway
	if gwID == "" {
		return host
	}
	gw, err := client.New().Host.Inspect(gwID, utils.GetExecutionTimeout())
	if err != nil {
		return nil
	}
	return gw
}