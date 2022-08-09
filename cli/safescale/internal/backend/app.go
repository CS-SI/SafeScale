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
	"fmt"
	"sync"

	"github.com/CS-SI/SafeScale/v22/cli/safescale/internal/common"
	appwide "github.com/CS-SI/SafeScale/v22/lib/utils/appwide"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/oscarpicas/covertool/pkg/exit"
	"github.com/spf13/cobra"
)

var cleanupOnce sync.Once

// SetCommands initializes
func SetCommands(rootCmd *cobra.Command) *cobra.Command {
	backendCmd := &cobra.Command{
		Use:     common.BackendCmdLabel,
		Aliases: []string{"daemon"},
		Short:   "Start SafeScale backend",
	}
	addFlags(backendCmd)
	addPreRunE(backendCmd)
	backendCmd.AddCommand(backendInitCommand, backendRunCommand, backendStopCommand)
	if rootCmd != nil {
		rootCmd.AddCommand(backendCmd)
		return rootCmd
	}
	return backendCmd
}

func Cleanup() {
	cleanupOnce.Do(func() {
		fmt.Println("Cleaning up...")

		exit.Exit(1)
	})
}

// AddPreRunE completes command PreRun with the necessary for backend
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
		// if c.Bool("help") {
		// 	return fail.NotAvailableError()
		// }

		// configFile, err := cmd.Flags().GetString("conf")
		// if err != nil {
		// 	return err
		// }
		//
		// rootDir, err := cmd.Flags().GetString("root-dir")
		// if err != nil {
		// 	return err
		// }

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
			return err
		}

		return nil
	}
	return nil
}

func addFlags(cmd *cobra.Command) {
	common.AddFlags(cmd)
	cmd.Flags().String("listen, l", "localhost:50051", "Listen on specified port `IP:PORT` (default: localhost:50051)")
	cmd.Flags().String("config, c", "", "Provides the configuration file to use (if needed) (default: <root-dir>/etc/settings.yml)")
	cmd.Flags().String("root-dir, R", "/opt/safescale", "Defines the root folder of safescale work tree; will overload content of configuration file (default: /opt/safescale)")
	cmd.Flags().String("etc-dir, E", "", "Defines the root folder of safescale work tree; will overload content of configuration file (default: <root-dir>/etc)")
	cmd.Flags().String("var-dir, V", "", "Defines the logs folder of safescale; will overload content of configuration file (default: <root-dir>/var)")
	cmd.Flags().String("log-dir, L", "", "Defines the logs folder of safescale; will overload content of configuration file (default: <var-dir>/log)")
	cmd.Flags().String("tmp-dir, T", "", "Defines the tmp folder of safescale; will overload content of configuration file (default: <var-dir>/tmp)")
	cmd.Flags().String("owner, O", "safescale", "Defines the user used on SafeScale folder tree; will overload content of configuration file (default: safescale)")
	cmd.Flags().String("group, G", "safescale", "Defines the user used on SafeScale folder tree; will overload content of configuration file (default: safescale)")
}
