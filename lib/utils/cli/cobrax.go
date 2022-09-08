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
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cli

import (
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/spf13/cobra"
)

// RootOfCommand returns the root *cobra.Command corresponding to the command tree from which the parameter is part of
func RootOfCommand(cmd *cobra.Command) (*cobra.Command, fail.Error) {
	if cmd == nil {
		return nil, fail.InvalidParameterCannotBeNilError("cmd")
	}

	prev := cmd
	for ; prev.HasParent(); prev = prev.Parent() {
	}

	return prev, nil
}

// ElderOfCommand identifies the 1st child in *cobra.Command tree from which parameter is part of
func ElderOfCommand(cmd *cobra.Command) (*cobra.Command, fail.Error) {
	if cmd == nil {
		return nil, fail.InvalidParameterCannotBeNilError("cmd")
	}

	prev := cmd
	for ; prev.HasParent() && prev.Parent().HasParent(); prev = prev.Parent() {
	}

	return prev, nil
}
