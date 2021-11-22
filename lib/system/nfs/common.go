/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"context"
	"fmt"
	"os"
	"strings"

	rice "github.com/GeertJohan/go.rice"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
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
			return nil, fail.ConvertError(err)
		}
	}
	return tmplBox, nil
}

// executeScript executes a script template with parameters in data map
// Returns retcode, stdout, stderr, error
// If error == nil && retcode != 0, the script ran but failed.
// func executeScript(task concurrency.Task, sshconfig system.SSHConfig, name string, data map[string]interface{}) (int, string, string, fail.Error) {
func executeScript(ctx context.Context, sshconfig system.SSHConfig, name string, data map[string]interface{}) (string, fail.Error) {
	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
			if xerr != nil {
				return "", xerr
			}
		default:
			return "", xerr
		}
	}

	if task.Aborted() {
		return "", fail.AbortedError(nil, "aborted")
	}

	bashLibraryDefinition, xerr := system.BuildBashLibraryDefinition()
	if xerr != nil {
		xerr = fail.ExecutionError(xerr)
		xerr.Annotate("retcode", 255)
		return "", xerr
	}

	mapped, xerr := bashLibraryDefinition.ToMap()
	if xerr != nil {
		return "", xerr
	}
	for k, v := range mapped {
		data[k] = v
	}
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
		xerr = fail.ExecutionError(err)
		_ = xerr.Annotate("retcode", 255)
		return "", xerr
	}

	// Prepare the template for execution
	tmplPrepared, err := template.Parse(name, tmplContent)
	if err != nil {
		xerr = fail.ExecutionError(err)
		xerr.Annotate("retcode", 255)
		return "", xerr
	}

	var buffer bytes.Buffer
	if err := tmplPrepared.Option("missingkey=error").Execute(&buffer, data); err != nil {
		xerr = fail.ExecutionError(err, "failed to execute template")
		xerr.Annotate("retcode", 255)
		return "", xerr
	}
	content := buffer.String()

	hidesOutput := strings.Contains(content, "set +x\n")
	if hidesOutput {
		content = strings.Replace(content, "set +x\n", "\n", 1)
	}

	// Copy script to remote host with retries if needed
	f, xerr := system.CreateTempFileFromString(content, 0666) // nolint
	if xerr != nil {
		xerr.Annotate("retcode", 255)
		return "", xerr
	}

	defer func() {
		if derr := utils.LazyRemove(f.Name()); derr != nil {
			logrus.Warnf("Error deleting file: %v", derr)
		}
	}()

	filename := utils.TempFolder + "/" + name
	xerr = retry.WhileUnsuccessful(
		func() error {
			retcode, stdout, stderr, innerXErr := sshconfig.CopyWithTimeout(ctx, filename, f.Name(), true, temporal.GetOperationTimeout())
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
		temporal.GetDefaultDelay(),
		temporal.GetHostTimeout(),
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry:
			return "", fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout:
			return "", fail.Wrap(fail.Cause(xerr), "timeout")
		case *fail.ErrExecution:
			return "", xerr
		default:
			yerr := fail.ExecutionError(xerr, "failed to copy script to remote host")
			_ = yerr.Annotate("retcode", 255)
			return "", yerr
		}
	}

	// Execute script on remote host with retries if needed
	var (
		cmd, stdout, stderr string
		retcode             int
	)

	if !hidesOutput {
		cmd = fmt.Sprintf("sync; chmod u+rwx %s; bash -x -c %s; exit ${PIPESTATUS}", filename, filename)
	} else {
		cmd = fmt.Sprintf("sync; chmod u+rwx %s; captf=$(mktemp); export BASH_XTRACEFD=7; bash -x -c %s 7>$captf 2>&1; rc=${PIPESTATUS}; cat $captf; rm $captf; exit ${rc}", filename, filename)
	}

	xerr = retry.Action(
		func() error {
			sshCmd, innerXErr := sshconfig.NewSudoCommand(ctx, cmd)
			if innerXErr != nil {
				return fail.ExecutionError(xerr)
			}
			defer func() { _ = sshCmd.Close() }()

			if retcode, stdout, stderr, innerXErr = sshCmd.RunWithTimeout(ctx, outputs.COLLECT, temporal.GetBigDelay()); innerXErr != nil {
				return fail.Wrap(innerXErr, "ssh operation failed")
			}

			return nil
		},
		retry.PrevailDone(retry.Unsuccessful(), retry.Timeout(temporal.GetContextTimeout())),
		retry.Constant(temporal.GetDefaultDelay()),
		nil, nil, nil,
	)
	if xerr != nil {
		switch cErr := xerr.(type) {
		case *fail.ErrTimeout:
			logrus.Errorf("ErrTimeout running remote script '%s'", name)
			xerr := fail.ExecutionError(cErr)
			xerr.Annotate("retcode", 255)
			// return 255, stdout, stderr, retryErr
			return stdout, xerr
		case *fail.ErrExecution:
			return stdout, cErr
		default:
			xerr = fail.ExecutionError(xerr)
			xerr.Annotate("retcode", 255).Annotate("stderr", "")
			// return 255, stdout, stderr, retryErr
			return stdout, xerr
		}
	}
	if retcode != 0 {
		xerr = fail.ExecutionError(nil, "command exited with error code '%d'", retcode)
		_ = xerr.Annotate("retcode", retcode).Annotate("stdout", stdout).Annotate("stderr", stderr)
		return stdout, xerr
	}

	return stdout, nil
}
