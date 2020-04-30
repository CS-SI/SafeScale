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

package nfs

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"text/template"

	rice "github.com/GeertJohan/go.rice"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

//go:generate rice embed-go

// templateProvider is the instance of TemplateProvider used by package nfs
var tmplBox *rice.Box

// getTemplateProvider returns the instance of TemplateProvider
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

// executeScript executes a script template with parameters in data map
// Returns retcode, stdout, stderr, error
// If error == nil && retcode != 0, the script ran but failed.
func executeScript(task concurrency.Task, sshconfig system.SSHConfig, name string, data map[string]interface{}) (int, string, string, error) {
	bashLibrary, err := system.GetBashLibrary()
	if err != nil {
		return 255, "", "", err
	}
	data["reserved_BashLibrary"] = bashLibrary
	data["Revision"] = system.REV

	scriptHeader := "set -u -o pipefail"
	if suffixCandidate := os.Getenv("SAFESCALE_SCRIPTS_FAIL_FAST"); suffixCandidate != "" {
		if strings.EqualFold("True", strings.TrimSpace(suffixCandidate)) {
			scriptHeader = "set -Eeuxo pipefail"
		}

		if strings.EqualFold("1", strings.TrimSpace(suffixCandidate)) {
			scriptHeader = "set -Eeuxo pipefail"
		}
	}

	data["BashHeader"] = scriptHeader

	tmplBox, err := getTemplateBox()
	if err != nil {
		return 255, "", "", err
	}

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
		return 255, "", "", fail.Wrap(err, "failed to execute template")
	}
	content := buffer.String()

	hidesOutput := strings.Contains(content, "set +x\n")
	if hidesOutput {
		content = strings.Replace(content, "set +x\n", "\n", 1)
		/*
			if strings.Contains(content, "exec 2>&1\n") {
				content = strings.Replace(content, "exec 2>&1\n", "exec 2>&7\n", 1)
			}
		*/
	}

	// Copy script to remote host with retries if needed
	f, err := system.CreateTempFileFromString(content, 0600)
	if err != nil {
		return 255, "", "", fail.Wrap(err, "failed to create temporary file")
	}
	filename := utils.TempFolder + "/" + name
	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			retcode, stdout, stderr, err := sshconfig.Copy(task, filename, f.Name(), true)
			if err != nil {
				return fail.Wrap(err, "ssh operation failed")
			}
			if retcode != 0 {
				return fail.NewReport("script copy failed: %s, %s", stdout, stderr)
			}
			return nil
		},
		temporal.GetHostTimeout(),
	)
	if retryErr != nil {
		return 255, "", "", fail.Wrap(err, "failed to copy script to remote host")
	}

	k, uperr := sshconfig.SudoCommand(task, "which scp")
	if uperr != nil && k != nil {
		_, uptext, _, kerr := k.RunWithTimeout(task, outputs.COLLECT, temporal.GetBigDelay())
		if kerr == nil {
			connected := strings.Contains(uptext, "/scp")
			if !connected {
				logrus.Warn("SUDO problem ?")
			}
		}
	}

	nerr := utils.LazyRemove(f.Name())
	if nerr != nil {
		logrus.Warnf("Report deleting file: %v", nerr)
	}

	// Execute script on remote host with retries if needed
	var (
		cmd, stdout, stderr string
		retcode             int
	)

	if !hidesOutput {
		cmd = fmt.Sprintf("chmod u+rwx %s; bash -c %s;exit ${PIPESTATUS}", filename, filename)
	} else {
		cmd = fmt.Sprintf("chmod u+rwx %s; export BASH_XTRACEFD=7; bash -c %s 7> /tmp/captured 2>&1;echo ${PIPESTATUS} > /tmp/errc;cat /tmp/captured; rm /tmp/captured;exit `cat /tmp/errc`", filename, filename)
	}

	retryErr = retry.Action(
		func() error {
			stdout = ""
			stderr = ""
			retcode = 0

			sshCmd, err := sshconfig.SudoCommand(task, cmd)
			if err != nil {
				return err
			}
			cmdResult, err := sshCmd.Output()
			stdout = string(cmdResult)
			stderr = ""
			retcode = 0
			if err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					if status, ok := ee.Sys().(syscall.WaitStatus); ok {
						retcode = status.ExitStatus()
					}
					stderr = string(ee.Stderr)
				}
			}
			return err
		},
		retry.PrevailDone(retry.UnsuccessfulWhereRetcode255(), retry.Timeout(temporal.GetContextTimeout())),
		retry.Constant(temporal.GetDefaultDelay()),
		nil, nil, nil,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrTimeout:
			logrus.Errorf("Timeout running remote script '%s'", name)
			return 255, stdout, stderr, retryErr
		default:
			return 255, stdout, stderr, retryErr
		}
	}

	/*
		k, uperr = sshconfig.SudoCommand("ping -c4 google.com")
		if uperr != nil {
			logrus.Warn("Network problem...")
		} else {
			_, uptext, _, kerr := k.Run()
			if kerr == nil {
				logrus.Warnf("Network working !!: %s", uptext)
			}
		}
	*/

	return retcode, stdout, stderr, err
}
