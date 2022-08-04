/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package commands

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/CS-SI/SafeScale/v22/lib/client"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	srvutils "github.com/CS-SI/SafeScale/v22/lib/server/utils"
	clitools "github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
)

var volumeCmdName = "volume"

// VolumeCommand volume command
var VolumeCommand = cli.Command{
	Name:  "volume",
	Usage: "volume COMMAND",
	Subcommands: cli.Commands{
		volumeList,
		volumeInspect,
		volumeDelete,
		volumeCreate,
		volumeAttach,
		volumeDetach,
	},
}

var volumeList = cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List available volumes",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "all, a",
			Usage: "List all Volumes on tenant (not only those created by SafeScale)",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", volumeCmdName, c.Command.Name, c.Args())

		defer interactiveFeedback("Listing volumes")()

		volumes, err := ClientSession.Volume.List(c.Bool("all"), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "list of volumes", false).Error())))
		}
		return clitools.SuccessResponse(volumes.Volumes)
	},
}

var volumeInspect = cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "Inspect volume",
	ArgsUsage: "<Volume_name|Volume_ID>",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", volumeCmdName, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Volume_name|Volume_ID>."))
		}

		defer interactiveFeedback("Inspect volume")()

		volumeInfo, err := ClientSession.Volume.Inspect(c.Args().First(), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "inspection of volume", false).Error())))
		}
		return clitools.SuccessResponse(toDisplayableVolumeInfo(volumeInfo))
	},
}

var volumeDelete = cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove"},
	Usage:     "Remove volume",
	ArgsUsage: "<Volume_name|Volume_ID> [<Volume_name|Volume_ID>...]",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", volumeCmdName, c.Command.Name, c.Args())
		if c.NArg() < 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Volume_name|Volume_ID>."))
		}

		var volumeList []string
		volumeList = append(volumeList, c.Args().First())
		volumeList = append(volumeList, c.Args().Tail()...)

		defer interactiveFeedback("Deleting volumes")()

		err := ClientSession.Volume.Delete(volumeList, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "deletion of volume", false).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var volumeCreate = cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "Create a volume",
	ArgsUsage: "<Volume_name>",
	Flags: []cli.Flag{
		cli.IntFlag{
			Name:  "size",
			Value: 10,
			Usage: "Size of the volume (in Go)",
		},
		cli.StringFlag{
			Name:  "speed",
			Value: "HDD",
			Usage: fmt.Sprintf("Allowed values: %s", getAllowedSpeeds()),
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", volumeCmdName, c.Command.Name, c.Args())
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Volume_name>. "))
		}

		speed := c.String("speed")
		volSpeed, ok := protocol.VolumeSpeed_value["VS_"+speed]
		if !ok {
			return clitools.FailureResponse(clitools.ExitOnInvalidOption(fmt.Sprintf("Invalid speed '%s'", speed)))
		}

		volSize := int32(c.Int("size"))
		if volSize <= 0 {
			return clitools.FailureResponse(clitools.ExitOnInvalidOption(fmt.Sprintf("Invalid volume size '%d', should be at least 1", volSize)))
		}

		def := protocol.VolumeCreateRequest{
			Name:  c.Args().First(),
			Size:  volSize,
			Speed: protocol.VolumeSpeed(volSpeed),
		}

		defer interactiveFeedback("Creating volumes")()

		volume, err := ClientSession.Volume.Create(&def, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "creation of volume", true).Error())))
		}
		return clitools.SuccessResponse(toDisplayableVolume(volume))
	},
}

var volumeAttach = cli.Command{
	Name:      "attach",
	Aliases:   []string{"bind"},
	Usage:     "Attach a volume to a host",
	ArgsUsage: "<Volume_name|Volume_ID> <Host_name|Host_ID>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "path",
			Value: abstract.DefaultVolumeMountPoint,
			Usage: "Mount point of the volume",
		},
		cli.StringFlag{
			Name:  "format",
			Value: "ext4",
			Usage: "Filesystem format",
		},
		cli.BoolFlag{
			Name:  "do-not-format",
			Usage: "Prevent the volume to be formatted (the previous format of the disk will be kept, beware that a new volume has no format before his first attachment and so would not be mounted with this option)",
		},
		cli.BoolFlag{
			Name:  "do-not-mount",
			Usage: "Prevent the volume to be mounted",
		},
	},
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", volumeCmdName, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Volume_name> and/or <Host_name>."))
		}

		def := protocol.VolumeAttachmentRequest{
			Format:      c.String("format"),
			DoNotFormat: c.Bool("do-not-format"),
			DoNotMount:  c.Bool("do-not-mount"),
			MountPath:   c.String("path"),
			Host:        &protocol.Reference{Name: c.Args().Get(1)},
			Volume:      &protocol.Reference{Name: c.Args().Get(0)},
		}

		defer interactiveFeedback("Attaching volumes")()

		err := ClientSession.Volume.Attach(&def, 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "attach of volume", true).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var volumeDetach = cli.Command{
	Name:      "detach",
	Aliases:   []string{"unbind"},
	Usage:     "Detach a volume from a host",
	ArgsUsage: "<Volume_name|Volume_ID> <Host_name|Host_ID>",
	Action: func(c *cli.Context) (ferr error) {
		defer fail.OnPanic(&ferr)
		logrus.Tracef("SafeScale command: %s %s with args '%s'", volumeCmdName, c.Command.Name, c.Args())
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Volume_name> and/or <Host_name>."))
		}

		defer interactiveFeedback("Detaching volumes")()

		err := ClientSession.Volume.Detach(c.Args().Get(0), c.Args().Get(1), 0)
		if err != nil {
			err = fail.FromGRPCStatus(err)
			return clitools.FailureResponse(clitools.ExitOnRPC(strprocess.Capitalize(client.DecorateTimeoutError(err, "unattach of volume", true).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

type attachmentInfoDisplayable struct {
	Host      string
	MountPath string
	Format    string
	Device    string
}

type volumeInfoDisplayable struct {
	ID          string
	Name        string
	Speed       string
	Size        int32
	Attachments []attachmentInfoDisplayable
	Mounted     bool
	Attached    bool
}

type volumeDisplayable struct {
	ID    string
	Name  string
	Speed string
	Size  int32
}

func toDisplayableVolumeInfo(volumeInfo *protocol.VolumeInspectResponse) *volumeInfoDisplayable {
	out := &volumeInfoDisplayable{
		ID:    volumeInfo.GetId(),
		Name:  volumeInfo.GetName(),
		Speed: protocol.VolumeSpeed_name[int32(volumeInfo.GetSpeed())],
		Size:  volumeInfo.GetSize(),
	}

	var mounted bool
	var links []attachmentInfoDisplayable
	attachments := volumeInfo.GetAttachments()
	for _, attach := range attachments {
		ref, _ := srvutils.GetReference(attach.GetHost())
		item := attachmentInfoDisplayable{
			Host:      ref,
			MountPath: attach.MountPath,
			Format:    attach.Format,
			Device:    attach.Device,
		}
		if attach.MountPath != "" {
			mounted = true
		}
		links = append(links, item)
	}

	out.Attached = len(attachments) > 0
	out.Attachments = links
	out.Mounted = mounted
	return out
}

func toDisplayableVolume(volumeInfo *protocol.VolumeInspectResponse) *volumeDisplayable {
	return &volumeDisplayable{
		volumeInfo.GetId(),
		volumeInfo.GetName(),
		protocol.VolumeSpeed_name[int32(volumeInfo.GetSpeed())],
		volumeInfo.GetSize(),
	}
}

func getAllowedSpeeds() string {
	speeds := ""
	i := 0
	for k := range protocol.VolumeSpeed_value {
		if i > 0 {
			speeds += ", "
		}
		// this message is intended for final users, showing allowed values that didn't match allowed inputs wasn't a good idea
		k = strings.TrimPrefix(k, "VS_")
		speeds += k
		i++
	}
	return speeds
}
