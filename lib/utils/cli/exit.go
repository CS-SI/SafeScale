/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/exitcode"
)

// ExitOnErrorWithMessage informs cli to exit with message and error code
func ExitOnErrorWithMessage(exitcode exitcode.Enum, msg string) error {
	return cli.NewExitError(msg, int(exitcode))
}

// ExitOnInvalidArgument ...
func ExitOnInvalidArgument(msg string) error {
	return ExitOnErrorWithMessage(exitcode.InvalidArgument, msg)
}

// ExitOnInvalidOption ...
func ExitOnInvalidOption(msg string) error {
	return ExitOnErrorWithMessage(exitcode.InvalidOption, msg)
}

// ExitOnRPC ...
func ExitOnRPC(msg string) error {
	return ExitOnErrorWithMessage(exitcode.RPC, msg)
}

// ExitOnNotFound ...
func ExitOnNotFound(msg string) error {
	return ExitOnErrorWithMessage(exitcode.NotFound, msg)
}
