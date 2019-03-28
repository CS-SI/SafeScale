package utils

import (
	"encoding/json"
	"fmt"

	"github.com/CS-SI/SafeScale/utils/enums/CmdStatus"
	urfcli "github.com/urfave/cli"
)

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

func NewCliResponse() CliResponse {
	return CliResponse{
		Status: CmdStatus.UNKNOWN,
		Error:  nil,
		Result: nil,
	}
}

func (cli *CliResponse) GetError() error {
	return cli.Error
}

func (cli *CliResponse) Succed(result interface{}) {
	cli.Status = CmdStatus.SUCCES
	cli.Result = result
	cli.Display()
}

func (cli *CliResponse) Failed(err error) error {
	cli.Status = CmdStatus.FAILURE
	if exitCoder, ok := err.(urfcli.ExitCoder); ok {
		cli.Error = exitCoder
	} else {
		panic("err is not an urfave/cli.ExitCoder")
	}
	cli.Display()
	return cli.GetError()
}

func (cli *CliResponse) Display() {
	out, err := json.Marshal(cli.getDisplayResponse())
	if err != nil {
		panic("Failed to marshal the CliResponse")
	}
	fmt.Println(string(out))
}

func (cli *CliResponse) getDisplayResponse() cliResponseDisplay {
	output := cliResponseDisplay{
		Status: cli.Status.String(),
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
