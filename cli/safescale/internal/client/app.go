package client

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/v22/cli/safescale/internal/client/commands"
	"github.com/CS-SI/SafeScale/v22/cli/safescale/internal/common"
	"github.com/CS-SI/SafeScale/v22/lib/backend/utils"
	"github.com/CS-SI/SafeScale/v22/lib/frontend/cmdline"
	clitools "github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/exitcode"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

func AddBefore(app *cli.App) error {
	precedentBefore := app.Before
	app.Before = func(c *cobra.Command, args []string) (err error) {
		if precedentBefore != nil {
			err := precedentBefore(c)
			if err != nil {
				return err
			}
		}

		common.LogSetup("", "cli")

		// Define trace settings of the application (what to trace if trace is wanted)
		// TODO: is it the good behavior ? Shouldn't we fail ?
		// If trace settings cannot be registered, report it but do not fail
		// TODO: introduce use of configuration file with autoreload on change
		err = tracing.RegisterTraceSettings(traceSettings())
		if err != nil {
			logrus.Errorf(err.Error())
		}

		// Create client session
		commands.ClientSession, err = cmdline.New(c.String("server"), c.String("tenant"))
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
func SetCommands(app *cobra.Command) {
	addFlags(commands.NetworkCommand)
	app.AddCommand(commands.NetworkCommand)
	//sort.Sort(cli.CommandsByName(commands.NetworkCommand.Subcommands))

	addFlags(commands.TenantCommand)
	app.AddCommand(commands.TenantCommand)
	//sort.Sort(cli.CommandsByName(commands.TenantCommand.Subcommands))

	addFlags(commands.HostCommand)
	app.AddCommand(commands.HostCommand)
	//sort.Sort(cli.CommandsByName(commands.HostCommand.Subcommands))

	addFlags(commands.VolumeCommand)
	app.AddCommand(commands.VolumeCommand)
	//sort.Sort(cli.CommandsByName(commands.VolumeCommand.Subcommands))

	addFlags(commands.SSHCommand)
	app.AddCommand(commands.SSHCommand)
	//sort.Sort(cli.CommandsByName(commands.SSHCommand.Subcommands))

	addFlags(commands.BucketCommand)
	app.AddCommand(commands.BucketCommand)
	//sort.Sort(cli.CommandsByName(commands.BucketCommand.Subcommands))

	addFlags(&commands.ShareCommand)
	app.AddCommand(commands.ShareCommand)
	//sort.Sort(cli.CommandsByName(commands.ShareCommand.Subcommands))

	addFlags(commands.ImageCommand)
	app.AddCommand(commands.ImageCommand)
	//sort.Sort(cli.CommandsByName(commands.ImageCommand.Subcommands))

	addFlags(commands.TemplateCommand)
	app.AddCommand(commands.TemplateCommand)
	//sort.Sort(cli.CommandsByName(commands.TemplateCommand.Subcommands))

	addFlags(commands.ClusterCommand)
	app.AddCommand(commands.ClusterCommand)
	//sort.Sort(cli.CommandsByName(commands.ClusterCommand.Subcommands))

	addFlags(commands.LabelCommand)
	app.AddCommand(commands.LabelCommand)
	//sort.Sort(cli.CommandsByName(commands.LabelCommand.Subcommands))

	addFlags(commands.TagCommand)
	app.AddCommand(commands.TagCommand)
	//sort.Sort(cli.CommandsByName(commands.TagCommand.Subcommands))

	app.AddCommand(backendcommands.BackendCommand)

	app.AddCommand(webuicommands.WebUICommand)

	sort.Sort(cli.CommandsByName(app.Commands))
}

func addFlags(cmd *cli.Command) {
	//common.AddFlags(&commands.TenantCommand)
	cmd.Flags = append(cmd.Flags, []cli.Flag{
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
