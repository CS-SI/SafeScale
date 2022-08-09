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

	"github.com/CS-SI/SafeScale/v22/cli/safescale/internal/common"
)

const initCmdLabel = "init"

var backendInitCommand = &cobra.Command{
	Use:   initCmdLabel,
	Short: "init SafeScale backend folder tree",
	RunE: func(cmd *cobra.Command, args []string) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", common.BackendCmdLabel, initCmdLabel, strings.Join(args, ", "))

		return initFolderTree(cmd)
	},
}

const runCmdLabel = "run"

var backendRunCommand = &cobra.Command{
	Use:   runCmdLabel,
	Short: "Start SafeScale backend",
	RunE: func(cmd *cobra.Command, args []string) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", common.BackendCmdLabel, runCmdLabel, strings.Join(args, ", "))
		return startBackend(cmd)
	},
}

const stopCmdLabel = "start"

var backendStopCommand = &cobra.Command{
	Use:   stopCmdLabel,
	Short: "stop SafeScale backend",
	RunE: func(cmd *cobra.Command, args []string) error {
		logrus.Tracef("SafeScale command: %s %s with args '%s'", common.BackendCmdLabel, stopCmdLabel, strings.Join(args, ", "))
		return stopBackend(cmd)
	},
}
