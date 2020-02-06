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

package payloads

import (
	"fmt"
	"os"
	"strings"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

func retrieveForensicsData(task concurrency.Task, host resources.Host) {
	if host == nil {
		return
	}
	if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
		hostName := host.Name()
		_ = os.MkdirAll(utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s", hostName)), 0777)
		dumpName := utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s/userdata-%s.", hostName, "phase2"))
		_, _, _, _ = host.Pull(task, "/opt/safescale/var/tmp/user_data.phase2.sh", dumpName+"sh", temporal.GetExecutionTimeout())
		_, _, _, _ = host.Pull(task, "/opt/safescale/var/log/user_data.phase2.log", dumpName+"log", temporal.GetExecutionTimeout())
	}
}

func getPhaseWarningsAndErrors(task concurrency.Task, host resources.Host) ([]string, []string) {
	if task == nil || host == nil {
		return []string{}, []string{}
	}

	recoverCode, recoverStdOut, _, recoverErr := host.Run(task, fmt.Sprintf("cat /opt/safescale/var/log/user_data.phase2.log; exit $?"), temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	warnings := []string{}
	errs := []string{}

	if recoverCode == 0 && recoverErr == nil {
		lines := strings.Split(recoverStdOut, "\n")
		for _, line := range lines {
			if strings.Contains(line, "An error occurred") {
				warnings = append(warnings, line)
			}
			if strings.Contains(line, "PROVISIONING_ERROR") {
				errs = append(errs, line)
			}
		}
	}

	return warnings, errs
}
