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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package backend

import (
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/CS-SI/SafeScale/v22/lib/global"
)

const initCmdLabel = "init"

const runCmdLabel = "run"

func runCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   runCmdLabel,
		Short: "Start SafeScale backend",
		RunE: func(cmd *cobra.Command, args []string) error {
			logrus.Tracef("SafeScale command: %s %s with args '%s'", global.BackendCmdLabel, runCmdLabel, strings.Join(args, ", "))
			return startBackend(cmd)
		},
	}

	addCommonFlags(out)
	flags := out.Flags()
	flags.StringP("listen", "L", "localhost:50051", "Defines host and port where backend server must listen (default: localhost:50080)")
	flags.String("bin-dir", "", "Defines the bin folder of safescale; will overload content of configuration file (default: <root-dir>/var)")
	flags.String("var-dir", "", "Defines the var folder of safescale; will overload content of configuration file (default: <root-dir>/var)")
	flags.String("log-dir", "", "Defines the logs folder of safescale; will overload content of configuration file (default: <var-dir>/log)")
	flags.String("tmp-dir", "", "Defines the tmp folder of safescale; will overload content of configuration file (default: <var-dir>/tmp)")
	flags.StringP("owner", "O", "safescale", "Defines the user used on SafeScale folder tree; will overload content of configuration file (default: safescale)")
	flags.StringP("group", "G", "safescale", "Defines the user used on SafeScale folder tree; will overload content of configuration file (default: safescale)")

	return out
}

const stopCmdLabel = "stop"

func stopCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   stopCmdLabel,
		Short: "stop SafeScale backend",
		RunE: func(cmd *cobra.Command, args []string) error {
			logrus.Tracef("SafeScale command: %s %s with args '%s'", global.BackendCmdLabel, stopCmdLabel, strings.Join(args, ", "))
			return stopBackend(cmd)
		},
	}

	addCommonFlags(out)

	return out
}

func addCommonFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.StringP("config", "c", "", "Provides the configuration file to use (if needed) (default: <root-dir>/etc/settings.yml)")
	flags.SetAnnotation("config", cobra.BashCompFilenameExt, global.ValidConfigFilenameExts)
	flags.StringP("root-dir", "R", "", "Defines the root folder of safescale work tree; will overload content of configuration file (default: /opt/safescale)")
	flags.StringP("etc-dir", "E", "", "Defines the root folder of safescale work tree; will overload content of configuration file (default: <root-dir>/etc)")
}
