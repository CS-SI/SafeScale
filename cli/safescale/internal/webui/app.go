package webui

import (
	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/v22/cli/safescale/internal/webui/commands"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

func Cleanup() {
	var crash error
	defer fail.SilentOnPanic(&crash) // nolint
}

func SetCommands(app *cli.App) {
	app.Commands = append(app.Commands, commands.WebUICommand)
}

func AddFlags(app *cli.App) {
	app.Flags = append(app.Flags, []cli.Flag{
		&cli.StringFlag{
			Name:  "server, S",
			Usage: "Connect to daemon on server SERVER (default: localhost:50051)",
			Value: "",
		},
	}...)
}
