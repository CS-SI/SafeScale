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

package nfs

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	rice "github.com/GeertJohan/go.rice"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/template"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

//go:generate rice embed-go

// templateProvider is the instance of TemplateProvider used by package nfs
var tmplBox *rice.Box

// getTemplateProvider returns the instance of TemplateProvider
func getTemplateBox() (*rice.Box, fail.Error) {
	if tmplBox == nil {
		var err error
		tmplBox, err = rice.FindBox("../nfs/scripts")
		if err != nil {
			return nil, fail.ToError(err)
		}
	}
	return tmplBox, nil
}

// executeScript executes a script template with parameters in data map
// Returns retcode, stdout, stderr, error
// If error == nil && retcode != 0, the script ran but failed.
// func executeScript(task concurrency.Task, sshconfig system.SSHConfig, name string, data map[string]interface{}) (int, string, string, fail.Error) {
func executeScript(task concurrency.Task, sshconfig system.SSHConfig, name string, data map[string]interface{}) (string, fail.Error) {
	bashLibrary, xerr := system.GetBashLibrary()
	if xerr != nil {
		xerr = fail.ExecutionError(xerr)
		xerr.Annotate("retcode", 255)
		// return 255, "", "", fail.ToError(err)
		return "", xerr
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
	tmplBox, xerr := getTemplateBox()
	if xerr != nil {
		xerr = fail.ExecutionError(xerr)
		xerr.Annotate("retcode", 255)
		return "", xerr
	}

	// get file content as string
	tmplContent, err := tmplBox.String(name)
	if err != nil {
		// return 255, "", "", fail.ToError(err)
		xerr = fail.ExecutionError(err)
		_ = xerr.Annotate("retcode", 255)
		// return 255, "", "", fail.ToError(err)
		return "", xerr
	}

	// Prepare the template for execution
	tmplPrepared, err := template.Parse(name, tmplContent)
	if err != nil {
		// return 255, "", "", fail.ToError(err)
		xerr = fail.ExecutionError(err)
		xerr.Annotate("retcode", 255)
		// return 255, "", "", fail.ToError(err)
		return "", xerr
	}

	var buffer bytes.Buffer
	if err := tmplPrepared.Execute(&buffer, data); err != nil {
		xerr = fail.ExecutionError(err, "failed to execute template")
		xerr.Annotate("retcode", 255)
		// return 255, "", "", fail.Wrap(err, "failed to execute template")
		return "", xerr
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
	f, xerr := system.CreateTempFileFromString(content, 0600)
	if xerr != nil {
		xerr.Annotate("retcode", 255)
		// return 255, "", "", fail.Wrap(err, "failed to create temporary file")
		return "", xerr
	}
	filename := utils.TempFolder + "/" + name
	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			retcode, stdout, stderr, innerXErr := sshconfig.Copy(task, filename, f.Name(), true)
			if innerXErr != nil {
				return fail.Wrap(innerXErr, "ssh operation failed")
			}
			if retcode != 0 {
				innerXErr = fail.ExecutionError(xerr, "script copy failed: %s, %s", stdout, stderr)
				_ = innerXErr.Annotate("retcode", retcode).Annotate("stdout", stdout).Annotate("stderr", stderr)
				return innerXErr
			}
			return nil
		},
		temporal.GetHostTimeout(),
	)
	if retryErr != nil {
		if _, ok := retryErr.(*fail.ErrExecution); ok {
			xerr = retryErr
		} else {
			xerr = fail.ExecutionError(retryErr, "failed to copy script to remote host")
			xerr.Annotate("retcode", 255)
		}
		// return 255, "", "", fail.Wrap(err, "failed to copy script to remote host")
		return "", xerr
	}

	k, uperr := sshconfig.SudoCommand(task, "which scp")
	if uperr != nil && k != nil {
		var uptext string
		retryErr := retry.WhileUnsuccessfulDelay5Seconds(
			func() error {
				var innerXErr fail.Error
				_, uptext, _, innerXErr = k.RunWithTimeout(task, outputs.COLLECT, temporal.GetBigDelay())
				if innerXErr != nil {
					return fail.Wrap(innerXErr, "ssh operation failed")
				}
				return nil
			},
			temporal.GetHostTimeout(),
		)
		if retryErr == nil {
			if connected := strings.Contains(uptext, "/scp"); !connected {
				logrus.Warn("SUDO problem ?")
			}
		}
	}

	if xerr = utils.LazyRemove(f.Name()); xerr != nil {
		logrus.Warnf("Error deleting file: %v", xerr)
	}

	// Execute script on remote host with retries if needed
	var (
		cmd, stdout string
		// retcode     int
	)

	if !hidesOutput {
		// cmd = fmt.Sprintf("chmod u+rwx %s; bash -c %s;exit ${PIPESTATUS}", filename, filename)
		cmd = fmt.Sprintf("bash -c %s;exit ${PIPESTATUS}", filename, filename)
	} else {
		// cmd = fmt.Sprintf("chmod u+rwx %s; export BASH_XTRACEFD=7; bash -c %s 7> /tmp/captured 2>&1;echo ${PIPESTATUS} > /tmp/errc;cat /tmp/captured; rm /tmp/captured;exit `cat /tmp/errc`", filename, filename)
		cmd = fmt.Sprintf("export BASH_XTRACEFD=7; bash -c %s 7> /tmp/captured 2>&1;echo ${PIPESTATUS} > /tmp/errc;cat /tmp/captured; rm /tmp/captured;exit `cat /tmp/errc`", filename, filename)
	}

	retryErr = retry.Action(
		func() error {
			stdout = ""
			// retcode = 0

			sshCmd, err := sshconfig.SudoCommand(task, cmd)
			if err != nil {
				return fail.ExecutionError(err)
			}
			cmdResult, err := sshCmd.Output()
			stdout = string(cmdResult)
			if err != nil {
				return fail.ExecutionError(err)
			}
			return nil
		},
		retry.PrevailDone(retry.UnsuccessfulWhereRetcode255(), retry.Timeout(temporal.GetContextTimeout())),
		retry.Constant(temporal.GetDefaultDelay()),
		nil, nil, nil,
	)
	if retryErr != nil {
		switch cErr := retryErr.(type) {
		case *fail.ErrTimeout:
			logrus.Errorf("ErrTimeout running remote script '%s'", name)
			xerr := fail.ExecutionError(cErr)
			xerr.Annotate("retcode", 255)
			// return 255, stdout, stderr, retryErr
			return stdout, xerr
		case *fail.ErrExecution:
			return stdout, cErr
		default:
			xerr = fail.ExecutionError(retryErr)
			xerr.Annotate("retcode", 255).Annotate("stderr", "")
			// return 255, stdout, stderr, retryErr
			return stdout, xerr
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

	// return retcode, stdout, stderr, err
	return stdout, nil
}
