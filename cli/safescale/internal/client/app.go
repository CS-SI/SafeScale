package client

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/v22/cli/safescale/internal/client/commands"
	daemoncommands "github.com/CS-SI/SafeScale/v22/cli/safescale/internal/daemon/commands"
	webuicommands "github.com/CS-SI/SafeScale/v22/cli/safescale/internal/webui/commands"
	libclient "github.com/CS-SI/SafeScale/v22/lib/client"
	"github.com/CS-SI/SafeScale/v22/lib/server/utils"
	clitools "github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

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

		// Create client session
		commands.ClientSession, err = libclient.New(c.String("server"), c.String("tenant"))
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnErrorWithMessage(exitcode.Run, err.Error()))
		}

		return nil
	}
	return nil
}

// once is used to ensure some code cannot be called multiple times during cleanup
var once sync.Once

func Cleanup() {
	var crash error
	defer fail.SilentOnPanic(&crash) // nolint

	fmt.Println("\nBe careful: stopping this command will not stop the job in daemon, but will try to go back to the previous state as much as possible.")
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Do you really want to stop the command ? [y]es [n]o: ")
	text, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("failed to read the input : ", err.Error())
		text = "y"
	}
	if strings.TrimRight(text, "\n") == "y" {
		once.Do(func() {

			err = commands.ClientSession.JobManager.Stop(utils.GetUUID(), temporal.ExecutionTimeout())
			if err != nil {
				fmt.Printf("failed to stop the process %v\n", err)
			}

			os.Exit(0)
		})
	}
}

// SetCommands sets the commands to react to
func SetCommands(app *cli.App) {
	app.Commands = append(app.Commands, commands.NetworkCommand)
	sort.Sort(cli.CommandsByName(commands.NetworkCommand.Subcommands))

	app.Commands = append(app.Commands, commands.TenantCommand)
	sort.Sort(cli.CommandsByName(commands.TenantCommand.Subcommands))

	app.Commands = append(app.Commands, commands.HostCommand)
	sort.Sort(cli.CommandsByName(commands.HostCommand.Subcommands))

	app.Commands = append(app.Commands, commands.VolumeCommand)
	sort.Sort(cli.CommandsByName(commands.VolumeCommand.Subcommands))

	app.Commands = append(app.Commands, commands.SSHCommand)
	sort.Sort(cli.CommandsByName(commands.SSHCommand.Subcommands))

	app.Commands = append(app.Commands, commands.BucketCommand)
	sort.Sort(cli.CommandsByName(commands.BucketCommand.Subcommands))

	app.Commands = append(app.Commands, commands.ShareCommand)
	sort.Sort(cli.CommandsByName(commands.ShareCommand.Subcommands))

	app.Commands = append(app.Commands, commands.ImageCommand)
	sort.Sort(cli.CommandsByName(commands.ImageCommand.Subcommands))

	app.Commands = append(app.Commands, commands.TemplateCommand)
	sort.Sort(cli.CommandsByName(commands.TemplateCommand.Subcommands))

	app.Commands = append(app.Commands, commands.ClusterCommand)
	sort.Sort(cli.CommandsByName(commands.ClusterCommand.Subcommands))

	app.Commands = append(app.Commands, commands.LabelCommand)
	sort.Sort(cli.CommandsByName(commands.LabelCommand.Subcommands))

	app.Commands = append(app.Commands, commands.TagCommand)
	sort.Sort(cli.CommandsByName(commands.TagCommand.Subcommands))

	// Integrate these commands for correct display of documentation
	app.Commands = append(app.Commands, daemoncommands.DaemonCommand)
	app.Commands = append(app.Commands, webuicommands.WebUICommand)

	sort.Sort(cli.CommandsByName(app.Commands))
}

func AddFlags(app *cli.App) {
	app.Flags = append(app.Flags, []cli.Flag{
		&cli.StringFlag{
			Name:  "server, S",
			Usage: "Connect to daemon on server SERVER (default: localhost:50051)",
			Value: "",
		},
		&cli.StringFlag{
			Name:  "tenant, T",
			Usage: "Use tenant TENANT (default: none)",
		},
	}...)
}
