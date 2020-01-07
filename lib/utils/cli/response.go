/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	urfcli "github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/cmdstatus"
)

// response define a standard response for most safescale commands
type response struct {
	Status cmdstatus.Enum
	Error  urfcli.ExitCoder
	Result interface{}
}

// jsonError ...
type jsonError struct {
	Message  string `json:"message"`
	ExitCode int    `json:"exitcode"`
}

// responseDisplay ...
type responseDisplay struct {
	Status string      `json:"status"`
	Error  *jsonError  `json:"error"`
	Result interface{} `json:"result"`
}

// newResponse ...
func newResponse() response {
	return response{
		Status: cmdstatus.UNKNOWN,
		Error:  nil,
		Result: nil,
	}
}

// GetError ...
func (r *response) GetError() error {
	return r.Error
}

// // GetErrorWithoutMessage ...
// func (r *response) GetErrorWithoutMessage() error {
// 	if r.Error != nil {
// 		return urfcli.NewExitError("", r.Error.ExitCode())
// 	}
// 	return nil
// }

// Success ...
func (r *response) Success(result interface{}) error {
	r.Status = cmdstatus.SUCCESS
	r.Result = result
	r.Display()
	return nil
}

// Failure ...
func (r *response) Failure(err error) error {
	if err != nil {
		r.Status = cmdstatus.FAILURE
		if exitCoder, ok := err.(urfcli.ExitCoder); ok {
			r.Error = exitCoder
			r.Display()
			return r.GetError()
		}
		logrus.Error("err is not an urfave/cli.ExitCoder")
		return err
	}
	return nil
}

// Display ...
func (r *response) Display() {
	out, err := json.Marshal(r.getDisplayResponse())
	if err != nil {
		logrus.Error("lib/utils/response.go: Response.Display(): failed to marshal the Response")
		return
	}

	if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
		if r.Status == cmdstatus.FAILURE {
			logrus.Error(string(out))
		} else {
			logrus.Warn(string(out))
		}
	}

	// Removed error if it's nil
	mapped := map[string]interface{}{}
	_ = json.Unmarshal(out, &mapped)
	if mapped["error"] == nil {
		delete(mapped, "error")
	}

	out, _ = json.Marshal(mapped)
	fmt.Println(string(out))
}

// getDisplayResponse ...
func (r *response) getDisplayResponse() responseDisplay {
	output := responseDisplay{
		Status: strings.ToLower(r.Status.String()),
		Error:  nil,
		Result: r.Result,
	}
	if r.Error != nil {
		output.Error = &jsonError{
			r.Error.Error(),
			r.Error.ExitCode(),
		}
	}
	return output
}

// FailureResponse ...
func FailureResponse(err error) error {
	r := newResponse()
	_ = r.Failure(err)
	if r.Error != nil {
		return urfcli.NewExitError("", r.Error.ExitCode())
	}
	return nil
}

// SuccessResponse ...
func SuccessResponse(result interface{}) error {
	r := newResponse()
	_ = r.Success(result)
	return nil
}
