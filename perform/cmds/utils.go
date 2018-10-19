/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

package cmds

import (
	"fmt"
	"os"
	"os/exec"

	clusterapi "github.com/CS-SI/SafeScale/deploy/cluster/api"
	"github.com/CS-SI/SafeScale/system"
	"github.com/CS-SI/SafeScale/utils/cli/ExitCode"
)

var (
	clusterName     string
	clusterInstance clusterapi.Cluster
	nodeName        string
	serviceName     string

	// RebrandingPrefix is used to store the optional prefix to use when calling external SafeScale commands
	RebrandingPrefix string
)

// RebrandCommand allows to prefix a command with cmds.RebrandingPrefix
// ie: with cmds.RebrandingPrefix == "safe "
//     "deploy ..." becomes "safe deploy ..."
//     with cmds.RebrandingPrefix == "my"
//     "perform ..." becomes "myperform ..."
func RebrandCommand(command string) string {
	return fmt.Sprintf("%s%s", RebrandingPrefix, command)
}

func runCommand(cmdStr string) int {
	cmd := exec.Command("bash", "-c", cmdStr)
	err := cmd.Run()
	if err != nil {
		msg, retcode, err := system.ExtractRetCode(err)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed to execute command")
			return int(ExitCode.Run)
		}
		_, _ = fmt.Fprintf(os.Stderr, msg)
		return retcode
	}
	return int(ExitCode.OK)
}
