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

package nfs

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/system"
	sshapi "github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/template"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

//go:embed scripts/*
var nfsScripts embed.FS

// executeScript executes a script template with parameters in data map
// Returns retcode, stdout, stderr, error
// If error == nil && retcode != 0, the script ran but failed.
func executeScript(
	ctx context.Context, timings temporal.Timings, sshconfig sshapi.Connector, name string,
	data map[string]interface{},
) (string, fail.Error) {
	currentCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		resOutput string
		resErr    fail.Error
	}

	resChan := make(chan result)
	go func() {
		defer close(resChan)
		bashLibraryDefinition, xerr := system.BuildBashLibraryDefinition(timings)
		if xerr != nil {
			xerr = fail.ExecutionError(xerr)
			resChan <- result{"", xerr}
			return
		}

		mapped, xerr := bashLibraryDefinition.ToMap()
		if xerr != nil {
			resChan <- result{"", xerr}
			return
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

		// get file content as string
		tmplContent, err := nfsScripts.ReadFile("scripts/" + name)
		if err != nil {
			resChan <- result{"", fail.ExecutionError(err)}
			return
		}

		// Prepare the template for execution
		tmplPrepared, err := template.Parse(name, string(tmplContent))
		if err != nil {
			resChan <- result{"", fail.ExecutionError(err)}
			return
		}

		var buffer bytes.Buffer
		err = tmplPrepared.Option("missingkey=error").Execute(&buffer, data)
		if err != nil {
			resChan <- result{"", fail.ExecutionError(err, "failed to execute template")}
			return
		}
		content := buffer.String()

		hidesOutput := strings.Contains(content, "set +x\n")
		if hidesOutput {
			content = strings.Replace(content, "set +x\n", "\n", 1)
		}

		// Copy script to remote host with retries if needed
		f, xerr := utils.CreateTempFileFromString(content, 0666) // nolint
		if xerr != nil {
			resChan <- result{"", xerr}
			return
		}

		defer func() {
			if derr := utils.LazyRemove(f.Name()); derr != nil {
				logrus.Debugf("Error deleting file: %v", derr)
			}
		}()

		transferTime := 30 * time.Second
		filename := utils.TempFolder + "/" + name
		xerr = retry.WhileUnsuccessful(
			func() error {
				fin, err := f.Stat()
				if err != nil {
					return err
				}

				transferTime = time.Duration(fin.Size())*time.Second/(64*1024) + 30*time.Second
				retcode, stdout, stderr, innerXErr := sshconfig.CopyWithTimeout(currentCtx, filename, f.Name(), true, transferTime)
				if innerXErr != nil {
					return fail.Wrap(innerXErr, "ssh operation failed")
				}
				if retcode != 0 {
					innerXErr := fail.ExecutionError(xerr, "script copy failed: %s, %s", stdout, stderr)
					innerXErr.Annotate("retcode", retcode).Annotate("stdout", stdout).Annotate("stderr", stderr)
					return innerXErr
				}

				return nil
			},
			timings.NormalDelay(),
			4*transferTime,
		)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrStopRetry:
				resChan <- result{"", fail.Wrap(fail.Cause(xerr), "stopping retries")}
				return
			case *retry.ErrTimeout:
				resChan <- result{"", fail.Wrap(fail.Cause(xerr), "timeout")}
				return
			case *fail.ErrExecution:
				resChan <- result{"", xerr}
				return
			default:
				yerr := fail.ExecutionError(xerr, "failed to copy script to remote host")
				resChan <- result{"", yerr}
				return
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
				var sshCmd sshapi.Command
				var innerXErr fail.Error
				defer func() {
					if sshCmd != nil {
						_ = sshCmd.Close()
					}
				}()

				sshCmd, innerXErr = sshconfig.NewSudoCommand(currentCtx, cmd)
				if innerXErr != nil {
					return fail.ExecutionError(xerr)
				}
				if retcode, stdout, stderr, innerXErr = sshCmd.RunWithTimeout(currentCtx, outputs.COLLECT, timings.ConnectionTimeout()+timings.HostOperationTimeout()); innerXErr != nil {
					return fail.Wrap(innerXErr, "ssh operation failed")
				}

				return nil
			},
			retry.PrevailDone(retry.Unsuccessful(), retry.Timeout(2*temporal.MaxTimeout(timings.ContextTimeout(), timings.ConnectionTimeout()+timings.HostOperationTimeout()))),
			retry.Constant(timings.NormalDelay()),
			nil, nil, nil,
		)
		if xerr != nil {
			switch cErr := xerr.(type) {
			case *fail.ErrTimeout:
				resChan <- result{stdout, fail.ExecutionError(cErr)}
				return
			case *fail.ErrExecution:
				resChan <- result{stdout, cErr}
				return
			default:
				tbr := fail.ExecutionError(xerr)
				tbr.Annotate("stderr", stderr)
				resChan <- result{stdout, tbr}
				return
			}
		}
		if retcode != 0 {
			xerr = fail.ExecutionError(nil, "command exited with error code '%d'", retcode)
			xerr.Annotate("retcode", retcode).Annotate("stdout", stdout).Annotate("stderr", stderr)
			resChan <- result{stdout, xerr}
			return
		}

		resChan <- result{stdout, nil}
	}()

	select {
	case res := <-resChan: // if it works return the return
		return res.resOutput, res.resErr
	case <-ctx.Done(): // if not because parent context was canceled
		return "", fail.ConvertError(ctx.Err())
	case <-currentCtx.Done(): // or timeout hits
		return "", fail.ConvertError(currentCtx.Err())
	}
}
