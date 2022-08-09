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

var webUIRunCommand = &cobra.Command{
	Use:   runCmdLabel,
	Short: "start SafeScale Web UI",
	RunE: func(cmd *cobra.Command, args []string) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", common.WebUICmdLabel, runCmdLabel, strings.Join(args, ", "))

		return run()
	},
}

const stopCmdLabel = "stop"

var webUIStopCommand = &cobra.Command{
	Use:   stopCmdLabel,
	Short: "Stop SafeScale Web UI",
	RunE: func(cmd *cobra.Command, args []string) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", common.WebUICmdLabel, stopCmdLabel, strings.Join(args, ", "))

		return fail.NotImplementedError("WebUI stop not implemented")
	},
}
