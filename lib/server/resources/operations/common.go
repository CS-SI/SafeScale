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

package operations

import (
    "fmt"
    "os"
    "strings"

    "github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
    "github.com/CS-SI/SafeScale/lib/server/resources"
    "github.com/CS-SI/SafeScale/lib/utils"
    "github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
    "github.com/CS-SI/SafeScale/lib/utils/concurrency"
    "github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// RetrieveForensicsData ...
// FIXME: documentation
func RetrieveForensicsData(task concurrency.Task, host resources.Host) {
    if host == nil {
        return
    }
    if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
        hostName := host.GetName()
        _ = os.MkdirAll(utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s", hostName)), 0777)

        dumpName := utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s/userdata-%s.", hostName, userdata.PHASE1_INIT))
        _, _, _, _ = host.Pull(task, fmt.Sprintf("/opt/safescale/var/tmp/user_data.%s.sh", string(userdata.PHASE1_INIT)), dumpName+"sh", temporal.GetExecutionTimeout())
        _, _, _, _ = host.Pull(task, fmt.Sprintf("/opt/safescale/var/log/user_data.%s.log", string(userdata.PHASE1_INIT)), dumpName+"log", temporal.GetExecutionTimeout())

        dumpName = utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s/userdata-%s.", hostName, userdata.PHASE2_NETWORK_AND_SECURITY))
        _, _, _, _ = host.Pull(task, fmt.Sprintf("/opt/safescale/var/tmp/user_data.%s.sh", string(userdata.PHASE2_NETWORK_AND_SECURITY)), dumpName+"sh", temporal.GetExecutionTimeout())
        _, _, _, _ = host.Pull(task, fmt.Sprintf("/opt/safescale/var/log/user_data.%s.log", string(userdata.PHASE2_NETWORK_AND_SECURITY)), dumpName+"log", temporal.GetExecutionTimeout())

        dumpName = utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s/userdata-%s.", hostName, userdata.PHASE3_GATEWAY_HIGH_AVAILABILITY))
        _, _, _, _ = host.Pull(task, fmt.Sprintf("/opt/safescale/var/tmp/user_data.%s.sh", string(userdata.PHASE3_GATEWAY_HIGH_AVAILABILITY)), dumpName+"sh", temporal.GetExecutionTimeout())
        _, _, _, _ = host.Pull(task, fmt.Sprintf("/opt/safescale/var/log/user_data.%s.log", string(userdata.PHASE3_GATEWAY_HIGH_AVAILABILITY)), dumpName+"log", temporal.GetExecutionTimeout())

        dumpName = utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s/userdata-%s.", hostName, userdata.PHASE4_SYSTEM_FIXES))
        _, _, _, _ = host.Pull(task, fmt.Sprintf("/opt/safescale/var/tmp/user_data.%s.sh", string(userdata.PHASE4_SYSTEM_FIXES)), dumpName+"sh", temporal.GetExecutionTimeout())
        _, _, _, _ = host.Pull(task, fmt.Sprintf("/opt/safescale/var/log/user_data.%s.log", string(userdata.PHASE4_SYSTEM_FIXES)), dumpName+"log", temporal.GetExecutionTimeout())

        dumpName = utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s/userdata-%s.", hostName, userdata.PHASE5_FINAL))
        _, _, _, _ = host.Pull(task, fmt.Sprintf("/opt/safescale/var/tmp/user_data.%s.sh", string(userdata.PHASE5_FINAL)), dumpName+"sh", temporal.GetExecutionTimeout())
        _, _, _, _ = host.Pull(task, fmt.Sprintf("/opt/safescale/var/log/user_data.%s.log", string(userdata.PHASE5_FINAL)), dumpName+"log", temporal.GetExecutionTimeout())
    }
}

// GetPhaseWarningsAndErrors ...
// FIXME: documentation
func GetPhaseWarningsAndErrors(task concurrency.Task, host resources.Host) ([]string, []string) {
    if task == nil || host == nil {
        return []string{}, []string{}
    }

    recoverCode, recoverStdOut, _, recoverErr := host.Run(task, `cat /opt/safescale/var/log/user_data.phase2.log; exit $?`, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
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
