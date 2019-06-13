/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
	"strings"

	log "github.com/sirupsen/logrus"
	urfcli "github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/CmdStatus"
)

// Response define a standard response to
type Response struct {
	Status CmdStatus.Enum
	Error  urfcli.ExitCoder
	Result interface{}
}

// jsonError ...
type jsonError struct {
	Message  string `json:"message"`
	ExitCode int    `json:"exitcode"`
}

// ResponseDisplay ...
type ResponseDisplay struct {
	Status string      `json:"status"`
	Error  *jsonError  `json:"error"`
	Result interface{} `json:"result"`
}

// NewResponse ...
func NewResponse() Response {
	return Response{
		Status: CmdStatus.UNKNOWN,
		Error:  nil,
		Result: nil,
	}
}

// GetError ...
func (r *Response) GetError() error {
	return r.Error
}

// GetErrorWithoutMessage ...
func (r *Response) GetErrorWithoutMessage() error {
	if r.Error != nil {
		return urfcli.NewExitError("", r.Error.ExitCode())
	}
	return nil
}

// Succeeded ...
func (r *Response) Succeeded(result interface{}) {
	r.Status = CmdStatus.SUCCESS
	r.Result = result
	r.Display()
}

// Failed ...
func (r *Response) Failed(err error) error {
	r.Status = CmdStatus.FAILURE
	if exitCoder, ok := err.(urfcli.ExitCoder); ok {
		r.Error = exitCoder
		r.Display()
		return r.GetError()
	}
	log.Error("err is not an urfave/cli.ExitCoder")
	return nil
}

// Display ...
func (r *Response) Display() {
	out, err := json.Marshal(r.getDisplayResponse())
	if err == nil {
		fmt.Println(string(out))
	} else {
		log.Error("Failed to marshal the Response")
	}
}

// getDisplayResponse ...
func (r *Response) getDisplayResponse() ResponseDisplay {
	output := ResponseDisplay{
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
