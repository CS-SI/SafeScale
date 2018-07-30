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

	cli "github.com/jawher/mow.cli"
)

// DcosCmd ...
func DcosCmd(cmd *cli.Cmd) {
	cmd.Spec = "-- [ARG...]"

	cmd.Action = func() {
		fmt.Println("not yet implemented")
	}
}

// KubectlCmd ...
func KubectlCmd(cmd *cli.Cmd) {
	cmd.Spec = "-- [ARG...]"

	cmd.Action = func() {
		fmt.Println("not yet implemented")
	}
}

// MarathonCmd ...
func MarathonCmd(cmd *cli.Cmd) {
	cmd.Spec = "-- [ARG...]"

	cmd.Action = func() {
		fmt.Println("not yet implemented")
	}
}
