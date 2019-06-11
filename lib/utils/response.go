package utils

import (
	"encoding/json"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	urfcli "github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/lib/utils/enums/CmdStatus"
)

// CliResponse define a standard response to
type CliResponse struct {
	Status CmdStatus.Enum
	Error  urfcli.ExitCoder
	Result interface{}
}

type jsonError struct {
	Message  string `json:"message"`
	ExitCode int    `json:"exitcode"`
}

type cliResponseDisplay struct {
	Status string      `json:"status"`
	Error  *jsonError  `json:"error"`
	Result interface{} `json:"result"`
}

// NewCliResponse ...
func NewCliResponse() CliResponse {
	return CliResponse{
		Status: CmdStatus.UNKNOWN,
		Error:  nil,
		Result: nil,
	}
}

// GetError ...
func (cli *CliResponse) GetError() error {
	return cli.Error
}

// GetErrorWithoutMessage ...
func (cli *CliResponse) GetErrorWithoutMessage() error {
	if cli.Error != nil {
		return urfcli.NewExitError("", cli.Error.ExitCode())
	}
	return nil
}

// Succeeded ...
func (cli *CliResponse) Succeeded(result interface{}) {
	cli.Status = CmdStatus.SUCCESS
	cli.Result = result
	cli.Display()
}

// Failed ...
func (cli *CliResponse) Failed(err error) error {
	if err != nil {
		cli.Status = CmdStatus.FAILURE
		if exitCoder, ok := err.(urfcli.ExitCoder); ok {
			cli.Error = exitCoder
			cli.Display()
			return cli.GetError()
		}
		log.Error("lib/utils/response.go: CliResponse.Failed(): err is not an urfave/cli.ExitCoder")
		return err
	}
	return nil
}

// Display ...
func (cli *CliResponse) Display() {
	out, err := json.Marshal(cli.getDisplayResponse())
	if err == nil {
		fmt.Println(string(out))
	} else {
		log.Error("lib/utils/response.go: CliResponse.Display(): failed to marshal the CliResponse")
	}
}

func (cli *CliResponse) getDisplayResponse() cliResponseDisplay {
	output := cliResponseDisplay{
		Status: strings.ToLower(cli.Status.String()),
		Error:  nil,
		Result: cli.Result,
	}
	if cli.Error != nil {
		output.Error = &jsonError{
			cli.Error.Error(),
			cli.Error.ExitCode(),
		}
	}
	return output
}
