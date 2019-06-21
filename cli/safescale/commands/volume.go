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

package commands

import (
	"fmt"

	"github.com/urfave/cli"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	safescaleutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils"
	clitools "github.com/CS-SI/SafeScale/lib/utils/cli"
)

//VolumeCmd volume command
var VolumeCmd = cli.Command{
	Name:  "volume",
	Usage: "volume COMMAND",
	Subcommands: []cli.Command{
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
			Name:  "all",
			Usage: "List all Volumes on tenant (not only those created by SafeScale)",
		}},
	Action: func(c *cli.Context) error {
		volumes, err := client.New().Volume.List(c.Bool("all"), client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "list of volumes", false).Error())))
		}
		return clitools.SuccessResponse(volumes.Volumes)
	},
}

var volumeInspect = cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show"},
	Usage:     "Inspect volume",
	ArgsUsage: "<Volume_name|Volume_ID>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Volume_name|Volume_ID>."))
		}

		volumeInfo, err := client.New().Volume.Inspect(c.Args().First(), client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "inspection of volume", false).Error())))
		}
		return clitools.SuccessResponse(toDisplaybleVolumeInfo(volumeInfo))
	},
}

var volumeDelete = cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "remove"},
	Usage:     "Delete volume",
	ArgsUsage: "<Volume_name|Volume_ID> [<Volume_name|Volume_ID>...]",
	Action: func(c *cli.Context) error {
		if c.NArg() < 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Volume_name|Volume_ID>."))
		}

		var volumeList []string
		volumeList = append(volumeList, c.Args().First())
		volumeList = append(volumeList, c.Args().Tail()...)

		err := client.New().Volume.Delete(volumeList, client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "deletion of volume", false).Error())))
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
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Volume_name>. "))
		}

		speed := c.String("speed")
		volSpeed, ok := pb.VolumeSpeed_value[speed]
		if !ok {
			return clitools.FailureResponse(clitools.ExitOnInvalidOption(fmt.Sprintf("Invalid speed '%s'", speed)))
		}
		volSize := int32(c.Int("size"))
		if volSize <= 0 {
			return clitools.FailureResponse(clitools.ExitOnInvalidOption(fmt.Sprintf("Invalid volume size '%d', should be at least 1", volSize)))
		}
		def := pb.VolumeDefinition{
			Name:  c.Args().First(),
			Size:  volSize,
			Speed: pb.VolumeSpeed(volSpeed),
		}

		volume, err := client.New().Volume.Create(def, client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "creation of volume", true).Error())))
		}
		return clitools.SuccessResponse(toDisplaybleVolume(volume))
	},
}

var volumeAttach = cli.Command{
	Name:      "attach",
	Usage:     "Attach a volume to an host",
	ArgsUsage: "<Volume_name|Volume_ID> <Host_name|Host_ID>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "path",
			Value: resources.DefaultVolumeMountPoint,
			Usage: "Mount point of the volume",
		},
		cli.StringFlag{
			Name:  "format",
			Value: "ext4",
			Usage: "Filesystem format",
		},
		cli.BoolFlag{
			Name:  "do-not-format",
			Usage: "Prevent the volume to be formated (the previous format of the disk will be kept, beware that a new volume has no format before his first attachment and so can't be attach with this option)",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Volume_name> and/or <Host_name>."))
		}
		def := pb.VolumeAttachment{
			Format:      c.String("format"),
			DoNotFormat: c.Bool("do-not-format"),
			MountPath:   c.String("path"),
			Host:        &pb.Reference{Name: c.Args().Get(1)},
			Volume:      &pb.Reference{Name: c.Args().Get(0)},
		}
		err := client.New().Volume.Attach(def, client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "attach of volume", true).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

var volumeDetach = cli.Command{
	Name:      "detach",
	Usage:     "Detach a volume from an host",
	ArgsUsage: "<Volume_name|Volume_ID> <Host_name|Host_ID>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 2 {
			_ = cli.ShowSubcommandHelp(c)
			return clitools.FailureResponse(clitools.ExitOnInvalidArgument("Missing mandatory argument <Volume_name> and/or <Host_name>."))
		}

		err := client.New().Volume.Detach(c.Args().Get(0), c.Args().Get(1), client.DefaultExecutionTimeout)
		if err != nil {
			return clitools.FailureResponse(clitools.ExitOnRPC(utils.Capitalize(client.DecorateError(err, "unattach of volume", true).Error())))
		}
		return clitools.SuccessResponse(nil)
	},
}

type volumeInfoDisplayable struct {
	ID        string
	Name      string
	Speed     string
	Size      int32
	Host      string
	MountPath string
	Format    string
	Device    string
}

type volumeDisplayable struct {
	ID    string
	Name  string
	Speed string
	Size  int32
}

func toDisplaybleVolumeInfo(volumeInfo *pb.VolumeInfo) *volumeInfoDisplayable {
	return &volumeInfoDisplayable{
		volumeInfo.GetId(),
		volumeInfo.GetName(),
		pb.VolumeSpeed_name[int32(volumeInfo.GetSpeed())],
		volumeInfo.GetSize(),
		safescaleutils.GetReference(volumeInfo.GetHost()),
		volumeInfo.GetMountPath(),
		volumeInfo.GetFormat(),
		volumeInfo.GetDevice(),
	}
}

func toDisplaybleVolume(volumeInfo *pb.Volume) *volumeDisplayable {
	return &volumeDisplayable{
		volumeInfo.GetId(),
		volumeInfo.GetName(),
		pb.VolumeSpeed_name[int32(volumeInfo.GetSpeed())],
		volumeInfo.GetSize(),
	}
}

func getAllowedSpeeds() string {
	speeds := ""
	i := 0
	for k := range pb.VolumeSpeed_value {
		if i > 0 {
			speeds += ", "
		}
		speeds += k
		i++
	}
	return speeds
}
