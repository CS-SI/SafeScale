/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"io/ioutil"
	"math"
	"os"
	"strings"
	"sync/atomic"
	"text/template"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/CS-SI/SafeScale/lib/utils/debug"

	"github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
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

# Redirects outputs to /opt/safescale/var/log/user_data.final.log
LOGFILE=%s/feature.{{.reserved_Name}}.{{.reserved_Action}}_{{.reserved_Step}}.log

### All output to one file and all output to the screen
exec > >(tee -a ${LOGFILE} /opt/safescale/var/log/ss.log) 2>&1
set -x

{{ .reserved_BashLibrary }}

waitForUserdata
sfDetectFacts

{{ .reserved_Content }}
`
)

// var featureScriptTemplate *template.Template
var featureScriptTemplate atomic.Value

// UploadFile uploads a file to remote host
func UploadFile(localpath string, host *pb.Host, remotepath, owner, group, rights string) (err error) {
	logrus.Debugf("UploadFile %s to %s starting...", remotepath, host.Name)
	defer func() {
		if err != nil {
			logrus.Debugf("UploadFile %s to %s failed with: %v", remotepath, host.Name, err)
		} else {
			logrus.Debugf("UploadFile %s to %s OK", remotepath, host.Name)
		}
	}()

	if localpath == "" {
		return fail.InvalidParameterError("localpath", "cannot be empty string")
	}
	if host == nil {
		return fail.InvalidParameterError("host", "cannot be nil")
	}
	if remotepath == "" {
		return fail.InvalidParameterError("remotepath", "cannot be empty string")
	}

	to := fmt.Sprintf("%s:%s", host.Name, remotepath)

	tracer := debug.NewTracer(
		nil, fmt.Sprintf("(%s, %s:%s)", localpath, host.Name, remotepath), true,
	).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	retryErr := retry.WhileUnsuccessful(
		func() error {
			logrus.Debug("Getting the SSH Client")
			sshClt := client.New().SSH
			logrus.Debug("Running the SSH copy client")
			retcode, _, _, err := sshClt.Copy(localpath, to, temporal.GetDefaultDelay(), 90*time.Second)
			logrus.Debug("Returning from SSH copy client")
			if err != nil {
				logrus.Warnf("Upload problem: %v", err)
				return err
			}
			if retcode == 0 {
				// it seems copy was ok, but make sure of it
				retcode, _, _, err = sshClt.Run(host.Name, fmt.Sprintf("test -s %s", remotepath), outputs.COLLECT, temporal.GetDefaultDelay(), 90 * time.Second)
				if err != nil {
					return err
				}
				if retcode != 0 {
					return fmt.Errorf("problem checking file %s on host %s: %d", remotepath, host.Name, retcode)
				}
				return nil
			}
			return fmt.Errorf("problem copying file %s on host %s: %d", remotepath, host.Name, retcode)
		},
		temporal.GetDefaultDelay(),
		temporal.GetLongOperationTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) { // nolint
		case retry.ErrTimeout:
			return fmt.Errorf("timeout trying to copy temporary file to '%s': %s", to, retryErr.Error())
		}
		return retryErr
	}

	cmd := ""
	if owner != "" {
		cmd += "sudo chown " + owner + " " + remotepath
	}
	if group != "" {
		if cmd != "" {
			cmd += " && "
		}
		cmd += "sudo chgrp " + group + " " + remotepath
	}
	if rights != "" {
		if cmd != "" {
			cmd += " && "
		}
		cmd += "sudo chmod " + rights + " " + remotepath
	}

	if len(cmd) > 0 {
		retryErr = retry.WhileUnsuccessful(
			func() error {
				var retcode int
				sshClt := client.New().SSH
				retcode, _, _, err = sshClt.Run(
					host.Name, cmd, outputs.COLLECT, temporal.GetDefaultDelay(), temporal.GetExecutionTimeout(),
				)
				if err != nil {
					if sta, ok := status.FromError(err); ok {
						if sta.Code() == codes.NotFound {
							return fail.AbortedError("not found", err)
						}
					}
					return err
				}
				if retcode != 0 {
					err = fmt.Errorf("failed to change rights of file '%s' (retcode=%d)", to, retcode)
					logrus.Warnf("hidden failure: %v", err)
					return nil
				}
				return nil
			},
			temporal.GetMinDelay(),
			temporal.GetLongOperationTimeout(),
		)
		if retryErr != nil {
			switch retryErr.(type) {
			case retry.ErrTimeout:
				return fmt.Errorf(
					"timeout trying to change rights of file '%s' on host '%s': %s", remotepath, host.Name, err.Error(),
				)
			default:
				return fmt.Errorf(
					"failed to change rights of file '%s' on host '%s': %s", remotepath, host.Name, retryErr.Error(),
				)
			}
		}
	}

	return nil
}

// UploadStringToRemoteFile creates a file 'filename' on remote 'host' with the content 'content'
func UploadStringToRemoteFile(content string, host *pb.Host, filename string, owner, group, rights string) error {
	if content == "" {
		return fail.InvalidParameterError("content", "cannot be empty string")
	}
	if host == nil {
		return fail.InvalidParameterError("host", "cannot be nil")
	}
	if filename == "" {
		return fail.InvalidParameterError("filename", "cannot be empty string")
	}

	if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
		_ = os.MkdirAll(utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s", host.Name)), 0777)
		partials := strings.Split(filename, "/")
		dumpName := utils.AbsPathify(
			fmt.Sprintf(
				"$HOME/.safescale/forensics/%s/%s", host.Name, partials[len(partials)-1],
			),
		)

		err := ioutil.WriteFile(dumpName, []byte(content), 0644)
		if err != nil {
			logrus.Warnf("[TRACE] Forensics error creating %s", dumpName)
		}
	}

	f, err := system.CreateTempFileFromString(content, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %s", err.Error())
	}

	err = UploadFile(f.Name(), host, filename, owner, group, rights)
	_ = os.Remove(f.Name())
	return err
}

// normalizeScript envelops the script with log redirection to /opt/safescale/var/log/feature.<name>.<action>.log
// and ensures BashLibrary are there
func normalizeScript(params map[string]interface{}) (string, error) {
	var (
		err         error
		tmplContent string
	)

	anon := featureScriptTemplate.Load()
	if anon == nil {
		if suffixCandidate := os.Getenv("SAFESCALE_SCRIPTS_FAIL_FAST"); suffixCandidate != "" {
			tmplContent = strings.Replace(featureScriptTemplateContent, "set -u -o pipefail", "set -Eeuxo pipefail", 1)
		} else {
			tmplContent = featureScriptTemplateContent
		}

		// parse then execute the template
		tmpl := fmt.Sprintf(tmplContent, utils.LogFolder, utils.LogFolder)
		result, err := template.New("normalize_script").Parse(tmpl)
		if err != nil {
			return "", fmt.Errorf("error parsing bash template: %s", err.Error())
		}
		featureScriptTemplate.Store(result)
		anon = featureScriptTemplate.Load()
	}

	// Configures BashLibrary template var
	bashLibrary, err := system.GetBashLibrary()
	if err != nil {
		return "", err
	}
	params["reserved_BashLibrary"] = bashLibrary

	params["TemplateOperationDelay"] = uint(math.Ceil(2 * temporal.GetDefaultDelay().Seconds()))
	params["TemplateOperationTimeout"] = strings.Replace(
		(temporal.GetHostTimeout() / 2).Truncate(time.Minute).String(), "0s", "", -1,
	)
	params["TemplateLongOperationTimeout"] = strings.Replace(
		temporal.GetHostTimeout().Truncate(time.Minute).String(), "0s", "", -1,
	)
	params["TemplatePullImagesTimeout"] = strings.Replace(
		(2 * temporal.GetHostTimeout()).Truncate(time.Minute).String(), "0s", "", -1,
	)

	dataBuffer := bytes.NewBufferString("")
	err = anon.(*template.Template).Execute(dataBuffer, params)
	if err != nil {
		return "", err
	}

	return dataBuffer.String(), nil
}

// realizeVariables replaces every variable in template
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

// func findConcernedHosts(list []string, c *Feature) (string, error) {
// 	// No metadata yet for features, first host is designated concerned host
// 	if len(list) > 0 {
// 		return list[0], nil
// 	}
// 	return "", fmt.Errorf("no hosts")
// 	//for _, h := range list {
// 	//}
// }

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
	gw, err := client.New().Host.Inspect(gwID, temporal.GetExecutionTimeout())
	if err != nil {
		return nil
	}
	return gw
}
