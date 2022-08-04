package daemon

import (
	"fmt"
	"sync"

	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/oscarpicas/covertool/pkg/exit"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/v22/cli/safescale/internal/daemon/commands"
)

var once sync.Once

func Cleanup() {
	once.Do(func() {
		fmt.Println("Cleaning up...")

		exit.Exit(1)
	})
}

func SetCommands(app *cli.App) {
	app.Commands = append(app.Commands, commands.DaemonCommand)
}

// SetBefore completes urfave/cli.App.Before with the necessary for daemon
func SetBefore(app *cli.App) error {
	precedentBefore := app.Before
	app.Before = func(c *cli.Context) (err error) {
		if precedentBefore != nil {
			err := precedentBefore(c)
			if err != nil {
				return err
			}
		}

		// Define trace settings of the application (what to trace if trace is wanted)
		// TODO: is it the good behavior ? Shouldn't we fail ?
		// If trace settings cannot be registered, report it but do not fail
		// TODO: introduce use of configuration file with autoreload on change
		err = tracing.RegisterTraceSettings(traceSettings())
		if err != nil {
			logrus.Errorf(err.Error())
		}

		return nil
	}
	return nil
}
