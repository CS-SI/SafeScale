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

package webui

import (
	"strings"

	"github.com/CS-SI/SafeScale/v22/cli/safescale/internal/common"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const runCmdLabel = "run"

func runCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   runCmdLabel,
		Short: "start SafeScale Web UI",
		RunE: func(cmd *cobra.Command, args []string) error {
			logrus.Tracef("SafeScale command: %s %s with args '%s'", common.WebUICmdLabel, runCmdLabel, strings.Join(args, ", "))

			return run()
		},
	}

	common.AddFlags(out)
	addCommonFlags(out)
	flags := out.Flags()
	flags.StringP("listen", "L", "localhost:50080", "Defines the backend server (default: localhost:50080)")
	flags.StringP("backend", "B", "localhost:50051", "Defines the backend server (default: localhost:50051)")
	flags.String("etc-dir", "", "Defines the root folder of safescale work tree; will overload content of configuration file (default: <root-dir>/etc)")
	flags.String("bin-dir", "", "Defines the bin folder of safescale; will overload content of configuration file (default: <root-dir>/var)")
	flags.String("var-dir", "", "Defines the var folder of safescale; will overload content of configuration file (default: <root-dir>/var)")
	flags.String("log-dir", "", "Defines the logs folder of safescale; will overload content of configuration file (default: <var-dir>/log)")
	flags.String("tmp-dir", "", "Defines the tmp folder of safescale; will overload content of configuration file (default: <var-dir>/tmp)")
	flags.StringP("owner", "O", "safescale", "Defines the user used on SafeScale folder tree; will overload content of configuration file (default: safescale)")
	flags.StringP("group", "G", "safescale", "Defines the user used on SafeScale folder tree; will overload content of configuration file (default: safescale)")
	flags.String("webroot", "", "path to Web UI files (mainly for debug)")
	return out
}

const stopCmdLabel = "stop"

func stopCommand() *cobra.Command {
	out := &cobra.Command{
		Use:   stopCmdLabel,
		Short: "Stop SafeScale Web UI",
		RunE: func(cmd *cobra.Command, args []string) error {
			logrus.Tracef("SafeScale command: %s %s with args '%s'", common.WebUICmdLabel, stopCmdLabel, strings.Join(args, ", "))

			return fail.NotImplementedError("WebUI stop not implemented")
		},
	}

	common.AddFlags(out)
	addCommonFlags(out)

	return out
}

func addCommonFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.StringP("config", "c", "", "Provides the configuration file to use (if needed) (default: <root-dir>/etc/settings.yml)")
	flags.SetAnnotation("config", cobra.BashCompFilenameExt, common.ValidConfigFilenameExts)
	flags.StringP("root-dir", "R", "/opt/safescale", "Defines the root folder of safescale work tree; will overload content of configuration file (default: /opt/safescale)")
}
