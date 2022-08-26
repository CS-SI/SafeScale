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
	"github.com/CS-SI/SafeScale/v22/lib/global"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func SetCommands() {
	out := &cobra.Command{
		Use:   global.WebUICmdLabel,
		Short: "Handles SafeScale web UI",
	}
	out.AddCommand(
		runCommand(),
		stopCommand(),
	)
	addPreRunE(out)

	global.AppCtrl.AddCommand(out)
}

// Cleanup ensure proper cleaning of WebUI on exit
func Cleanup() {
	var crash error
	defer fail.SilentOnPanic(&crash) // nolint
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
