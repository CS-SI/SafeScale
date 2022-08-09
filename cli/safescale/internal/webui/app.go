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
	"fmt"
	"strings"

	"github.com/CS-SI/SafeScale/v22/cli/safescale/internal/common"
	appwide "github.com/CS-SI/SafeScale/v22/lib/utils/appwide"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func SetCommands(rootCmd *cobra.Command) *cobra.Command {
	out := &cobra.Command{
		Use:   common.WebUICmdLabel,
		Short: "Handles SafeScale web UI",
		RunE: func(cmd *cobra.Command, args []string) (ferr error) {
			logrus.Tracef("SafeScale command: %s with args '%s'", cmd.Name(), strings.Join(args, ", "))

			run()

			return nil
		},
	}
	addFlags(out)
	addPreRunE(out)
	if rootCmd != nil {
		rootCmd.AddCommand(out)
		return rootCmd
	}
	return out
}

func Cleanup() {
	var crash error
	defer fail.SilentOnPanic(&crash) // nolint
}

// func SetCommands(app *cobra.Command) {
// 	addFlags(&WebUICommand)
// 	app.Commands = append(app.Commands, WebUICommand)
// }

func addFlags(cmd *cobra.Command) {
	common.AddFlags(cmd)
	cmd.Flags().String("listen", "localhost:50080", "Defines the backend server (default: localhost:50080)")
	cmd.Flags().String("backend, B", "localhost:50051", "Defines the backend server (default: localhost:50051)")
	cmd.Flags().String("config, c", "", "Provides the configuration file to use (if needed) (default: <root-dir>/etc/settings.yml)")
	cmd.Flags().String("root-dir, R", "/opt/safescale", "Defines the root folder of safescale work tree; will overload content of configuration file (default: /opt/safescale)")
	cmd.Flags().String("etc-dir, E", "", "Defines the root folder of safescale work tree; will overload content of configuration file (default: <root-dir>/etc)")
	cmd.Flags().String("var-dir, V", "", "Defines the logs folder of safescale; will overload content of configuration file (default: <root-dir>/var)")
	cmd.Flags().String("log-dir, L", "", "Defines the logs folder of safescale; will overload content of configuration file (default: <var-dir>/log)")
	cmd.Flags().String("tmp-dir, T", "", "Defines the tmp folder of safescale; will overload content of configuration file (default: <var-dir>/tmp)")
}

// addPreRunE completes PreRunE of the command with the necessary for webui
func addPreRunE(cmd *cobra.Command) error {
	previousPreRunE := cmd.PreRunE
	cmd.PreRunE = func(cmd *cobra.Command, args []string) (err error) {
		if previousPreRunE != nil {
			err := previousPreRunE(cmd, args)
			if err != nil {
				return err
			}
		}

		// If --help is used, fail to fallback to cli
		help, err := cmd.Flags().GetBool("help")
		if err != nil {
			return err
		}
		if help {
			return fail.NotAvailableError()
		}

		xerr := appwide.LoadSettings(cmd, args)
		if xerr != nil {
			return fmt.Errorf(xerr.Error() + ". Halted.")
		}

		// Define trace settings of the application (what to trace if trace is wanted)
		// TODO: is it the good behavior ? Shouldn't we fail ?
		// If trace settings cannot be registered, report it but do not fail
		// TODO: introduce use of configuration file with autoreload on change
		err = tracing.RegisterTraceSettings(traceSettings())
		if err != nil {
			logrus.Errorf(err.Error())
		}

		return nil
	}
	return nil
}
