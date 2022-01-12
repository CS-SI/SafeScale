/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

package bucketfs

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	rice "github.com/GeertJohan/go.rice"
	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/template"
)

//go:generate rice embed-go

// templateProvider is the instance of TemplateProvider used by package bucketfs
var tmplBox *rice.Box

// getTemplateProvider returns the instance of TemplateProvider
func getTemplateBox() (*rice.Box, fail.Error) {
	if tmplBox == nil {
		var err error
		tmplBox, err = rice.FindBox("../bucketfs/scripts")
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
func executeScript(ctx context.Context, host resources.Host, name string, data map[string]interface{}) fail.Error {
	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
			if xerr != nil {
				return xerr
			}
		default:
			return xerr
		}
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	bashLibraryDefinition, xerr := system.BuildBashLibraryDefinition(host.Service().Timings())
	if xerr != nil {
		xerr = fail.ExecutionError(xerr)
		return xerr
	}

	mapped, xerr := bashLibraryDefinition.ToMap()
	if xerr != nil {
		return xerr
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

	content, xerr := realizeTemplate(name, data)
	if xerr != nil {
		return xerr
	}

	hidesOutput := strings.Contains(content, "set +x\n")
	if hidesOutput {
		content = strings.Replace(content, "set +x\n", "\n", 1)
	}

	filename, xerr := uploadContentToFile(ctx, content, name, "", "", host)
	if xerr != nil {
		return xerr
	}

	// Execute script on remote host with retries if needed
	var (
		cmd, stdout, stderr string
		retcode             int
	)

	if !hidesOutput {
		cmd = fmt.Sprintf("sync; chmod u+rwx %s; sudo bash -x -c %s; exit ${PIPESTATUS}", filename, filename)
	} else {
		cmd = fmt.Sprintf("sync; chmod u+rwx %s; captf=$(mktemp); export BASH_XTRACEFD=7; sudo bash -x -c %s 7>$captf 2>&1; rc=${PIPESTATUS}; cat $captf; rm $captf; exit ${rc}", filename, filename)
	}

	xerr = retry.Action(
		func() (innerXErr error) {
			retcode, stdout, stderr, innerXErr = host.Run(ctx, cmd, outputs.COLLECT, host.Service().Timings().ConnectionTimeout(), host.Service().Timings().BigDelay())
			if innerXErr != nil {
				return fail.Wrap(innerXErr, "ssh operation failed")
			}

			return nil
		},
		retry.PrevailDone(retry.Unsuccessful(), retry.Timeout(host.Service().Timings().ContextTimeout())),
		retry.Constant(host.Service().Timings().NormalDelay()),
		nil, nil, nil,
	)
	if xerr != nil {
		switch cErr := xerr.(type) {
		case *fail.ErrTimeout:
			logrus.Errorf("ErrTimeout running remote script '%s'", name)
			xerr := fail.ExecutionError(cErr)
			return xerr
		case *fail.ErrExecution:
			return cErr
		default:
			xerr = fail.ExecutionError(xerr)
			xerr.Annotate("stderr", "")
			return xerr
		}
	}
	if retcode != 0 {
		xerr = fail.ExecutionError(nil, "command exited with error code '%d'", retcode)
		xerr.Annotate("retcode", retcode).Annotate("stdout", stdout).Annotate("stderr", stderr)
		return xerr
	}

	return nil
}

func realizeTemplate(name string, data interface{}) (string, fail.Error) {
	tmplBox, xerr := getTemplateBox()
	if xerr != nil {
		xerr = fail.ExecutionError(xerr, "failure retrieving embedded blobs")
		return "", xerr
	}

	// get file content as string
	tmplContent, err := tmplBox.String(name)
	if err != nil {
		xerr = fail.ExecutionError(err, "failure retrieving embedded box '%s'", name)
		return "", xerr
	}

	// Prepare the template for execution
	tmplPrepared, err := template.Parse(name, tmplContent)
	if err != nil {
		xerr = fail.ExecutionError(err, "failure parsing template '%s'", name)
		return "", xerr
	}

	var buffer bytes.Buffer
	if err := tmplPrepared.Option("missingkey=error").Execute(&buffer, data); err != nil {
		// log the faulty data
		logrus.Debugf("failure to execute template '%s' due to unrendered data, data at fault: '%s'", name, spew.Sdump(data))
		xerr = fail.ExecutionError(err, "failed to execute template '%s' due to unrendered values", name)
		return "", xerr
	}
	content := buffer.String()
	return content, nil
}

func uploadContentToFile(
	ctx context.Context, content, name, owner, rights string, host resources.Host,
) (string, fail.Error) {
	// Copy script to remote host with retries if needed
	f, xerr := system.CreateTempFileFromString(content, 0666) // nolint
	if xerr != nil {
		return "", xerr
	}

	defer func() {
		if derr := utils.LazyRemove(f.Name()); derr != nil {
			logrus.Warnf("Error deleting file: %v", derr)
		}
	}()

	// TODO: This is not Windows friendly
	svc := host.Service()
	filename := utils.TempFolder + "/" + name
	xerr = retry.WhileUnsuccessful(
		func() error {
			retcode, stdout, stderr, innerXErr := host.Push(ctx, f.Name(), filename, owner, rights, svc.Timings().OperationTimeout())
			if innerXErr != nil {
				return fail.Wrap(innerXErr, "failed to upload content to remote")
			}
			if retcode != 0 {
				innerXErr = fail.ExecutionError(xerr, "failed to copy content: %s, %s", stdout, stderr)
				innerXErr.Annotate("retcode", retcode).Annotate("stdout", stdout).Annotate("stderr", stderr)
				return innerXErr
			}

			return nil
		},
		svc.Timings().NormalDelay(),
		svc.Timings().HostOperationTimeout(),
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry:
			if cerr := fail.Cause(xerr); cerr != nil {
				return "", fail.Wrap(fail.Cause(xerr), "stopping retries")
			}
			return "", xerr
		case *retry.ErrTimeout:
			if cerr := fail.Cause(xerr); cerr != nil {
				return "", fail.Wrap(fail.Cause(xerr), "timeout")
			}
			return "", xerr
		case *fail.ErrExecution:
			return "", xerr
		default:
			xerr = fail.ExecutionError(xerr, "failed to copy script to remote host")
			return "", xerr
		}
	}
	return filename, nil
}
