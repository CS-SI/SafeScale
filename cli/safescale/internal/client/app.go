package client

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/CS-SI/SafeScale/v22/cli/safescale/internal/client/commands"
	"github.com/CS-SI/SafeScale/v22/lib/backend/utils"
	"github.com/CS-SI/SafeScale/v22/lib/global"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

// cleanupOnce is used to ensure some code cannot be called multiple times during cleanup
var cleanupOnce sync.Once

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
		cleanupOnce.Do(func() {
			err = commands.ClientSession.JobManager.Stop(utils.GetUUID(), temporal.ExecutionTimeout())
			if err != nil {
				fmt.Printf("failed to stop the process %v\n", err)
			}

			os.Exit(0)
		})
	}
}

// SetCommands sets the commands to react to
func SetCommands() {
	global.AppCtrl.AddCommand(
		commands.BucketCommands(),
		commands.ClusterCommands(),
		commands.HostCommands(),
		commands.ImageCommands(),
		commands.LabelCommands(),
		commands.NetworkCommands(),
		commands.ShareCommands(),
		commands.SSHCommands(),
		commands.TagCommands(),
		commands.TemplateCommands(),
		commands.TenantCommands(),
		commands.VolumeCommands(),
	)
}
