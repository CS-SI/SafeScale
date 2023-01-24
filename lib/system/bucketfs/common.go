/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	iaasapi "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/system"
	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/template"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

// hostTarget is a subnet of *resources.Host to use in the package, to prevent import cycle
type hostTarget interface {
	Run(context.Context, string, outputs.Enum, time.Duration, time.Duration) (int, string, string, fail.Error)
	Service() iaasapi.Service
	Push(ctx context.Context, source, target, owner, mode string, timeout time.Duration) (_ int, _ string, _ string, ferr fail.Error)
}

//go:embed scripts/*
var bucketfsScripts embed.FS

// executeScript executes a script template with parameters in data map
// Returns retcode, stdout, stderr, error
// If error == nil && retcode != 0, the script ran but failed.
// func executeScript(ctx context.Context, sshconfig ssh.Profile, name string, data map[string]interface{}) (int, string, string, fail.Error) {
func executeScript(ctx context.Context, host hostTarget, name string, data map[string]interface{}) fail.Error {
	timings, xerr := host.Service().Timings()
	if xerr != nil {
		return xerr
	}

	bashLibraryDefinition, xerr := system.BuildBashLibraryDefinition(timings)
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
			retcode, stdout, stderr, innerXErr = host.Run(ctx, cmd, outputs.COLLECT, timings.ConnectionTimeout(), timings.ExecutionTimeout())
			if innerXErr != nil {
				return fail.Wrap(innerXErr, "ssh operation failed")
			}

			return nil
		},
		retry.PrevailDone(retry.Unsuccessful(), retry.Timeout(2*temporal.MaxTimeout(timings.ContextTimeout(), timings.ConnectionTimeout()+timings.ExecutionTimeout()))),
		retry.Constant(timings.NormalDelay()),
		nil, nil, nil,
	)
	if xerr != nil {
		switch cErr := xerr.(type) {
		case *fail.ErrTimeout:
			logrus.WithContext(ctx).Errorf("ErrTimeout running remote script '%s'", name)
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
	// get file content as string
	tmplContent, err := bucketfsScripts.ReadFile("scripts/" + name)
	if err != nil {
		return "", fail.ExecutionError(err, "failure retrieving embedded box '%s'", name)
	}

	// Prepare the template for execution
	tmplPrepared, err := template.Parse(name, string(tmplContent))
	if err != nil {
		return "", fail.ExecutionError(err, "failure parsing template '%s'", name)
	}

	var buffer bytes.Buffer
	if err := tmplPrepared.Option("missingkey=error").Execute(&buffer, data); err != nil {
		// log the faulty data
		return "", fail.ExecutionError(err, "failed to execute template '%s' due to unrendered data, data at fault: '%s'", name, spew.Sdump(data))
	}
	content := buffer.String()
	return content, nil
}

func uploadContentToFile(ctx context.Context, content, name, owner, rights string, host hostTarget) (string, fail.Error) {
	// Copy script to remote host with retries if needed
	f, xerr := utils.CreateTempFileFromString(content, 0666) // nolint
	if xerr != nil {
		return "", xerr
	}

	defer func() {
		derr := utils.LazyRemove(f.Name())
		if derr != nil {
			logrus.WithContext(ctx).Warnf("Error deleting file: %v", derr)
		}
	}()

	// TODO: This is not Windows friendly
	svc := host.Service()

	timings, xerr := svc.Timings()
	if xerr != nil {
		return "", xerr
	}

	filename := filepath.Join(utils.TempFolder, name)
	xerr = retry.WhileUnsuccessful(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			retcode, stdout, stderr, innerXErr := host.Push(ctx, f.Name(), filename, owner, rights, timings.OperationTimeout())
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
		timings.NormalDelay(),
		timings.HostOperationTimeout(),
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
