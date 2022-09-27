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
	"github.com/spf13/cobra"

	srvutils "github.com/CS-SI/SafeScale/v22/lib/backend/common"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/frontend/cmdline"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
)

const volumeCmdLabel = "volume"

// VolumeCommands volume commands
func VolumeCommands() *cobra.Command {
	out := &cobra.Command{
		Use:   "volume",
		Short: "volume COMMAND",
	}
	out.AddCommand(
		volumeListCommand(),
		volumeInspectCommand(),
		volumeDeleteCommand(),
		volumeCreateCommand(),
		volumeAttachCommand(),
		volumeDetachCommand(),
	)
	addPersistentPreRunE(out)
	addCommonFlags(out)
	return out
}

func volumeListCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List available volumes",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", volumeCmdLabel, c.Name(), strings.Join(args, ", "))

			all, err := c.Flags().GetBool("all")
			if err != nil {
				return err
			}

			volumes, err := ClientSession.Volume.List(all, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "list of volumes", false).Error())))
			}
			return cli.SuccessResponse(volumes.Volumes)
		},
	}

	out.Flags().BoolP("all", "a", false, "List all Volumes on tenant (not only those created by SafeScale)")

	return out
}

func volumeInspectCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "inspect",
		Aliases: []string{"show"},
		Short:   "Inspect volume",
		// ArgsUsage: "<Volume_name|Volume_ID>",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", volumeCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) != 1 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument <Volume_name|Volume_ID>."))
			}

			volumeInfo, err := ClientSession.Volume.Inspect(args[0], 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "inspection of volume", false).Error())))
			}

			return cli.SuccessResponse(toDisplayableVolumeInfo(volumeInfo))
		},
	}
	return out
}

func volumeDeleteCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "delete",
		Aliases: []string{"rm", "remove"},
		Short:   "Remove volume",
		// ArgsUsage: "<Volume_name|Volume_ID> [<Volume_name|Volume_ID>...]",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", volumeCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) < 1 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument <Volume_name|Volume_ID>."))
			}

			err := ClientSession.Volume.Delete(args, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "deletion of volume", false).Error())))
			}

			return cli.SuccessResponse(nil)
		},
	}
	return out
}

func volumeCreateCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "create",
		Aliases: []string{"new"},
		Short:   "Create a volume",
		// ArgsUsage: "<Volume_name>",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", volumeCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) != 1 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument <Volume_name>. "))
			}

			speed, err := c.Flags().GetString("speed")
			if err != nil {
				return err
			}

			volSpeed, ok := protocol.VolumeSpeed_value["VS_"+speed]
			if !ok {
				return cli.FailureResponse(cli.ExitOnInvalidOption(fmt.Sprintf("Invalid speed '%s'", speed)))
			}

			volSize, err := c.Flags().GetInt("size")
			if err != nil {
				return err
			}

			if volSize <= 0 {
				return cli.FailureResponse(cli.ExitOnInvalidOption(fmt.Sprintf("Invalid volume size '%d', should be at least 1", volSize)))
			}

			def := protocol.VolumeCreateRequest{
				Name:  args[0],
				Size:  int32(volSize),
				Speed: protocol.VolumeSpeed(volSpeed),
			}

			volume, err := ClientSession.Volume.Create(&def, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "creation of volume", true).Error())))
			}

			return cli.SuccessResponse(toDisplayableVolume(volume))
		},
	}

	flags := out.Flags()
	flags.Uint("size", 10, "Size of the volume (in GB)")
	flags.String("speed", "HDD", fmt.Sprintf("Allowed values: %s", getAllowedSpeeds()))

	return out
}

func volumeAttachCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "attach",
		Aliases: []string{"bind"},
		Short:   "Attach a volume to a host",
		// ArgsUsage: "<Volume_name|Volume_ID> <Host_name|Host_ID>",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", volumeCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) != 2 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument <Volume_name> and/or <Host_name>."))
			}

			def := protocol.VolumeAttachmentRequest{
				Host:   &protocol.Reference{Name: args[1]},
				Volume: &protocol.Reference{Name: args[0]},
			}

			var err error
			flags := c.Flags()
			def.Format, err = flags.GetString("format")
			if err != nil {
				return err
			}

			def.DoNotFormat, err = flags.GetBool("do-not-format")
			if err != nil {
				return err
			}

			def.DoNotMount, err = flags.GetBool("do-not-mount")
			if err != nil {
				return err
			}

			def.MountPath, err = flags.GetString("path")
			if err != nil {
				return err
			}

			err = ClientSession.Volume.Attach(&def, 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "attach of volume", true).Error())))
			}

			return cli.SuccessResponse(nil)
		},
	}

	flags := out.Flags()
	flags.String("path", abstract.DefaultVolumeMountPoint, "Mount point of the volume")
	flags.String("format", "ext4", "Filesystem format")
	flags.Bool("do-not-format", false, "Prevent the volume to be formatted (the previous format of the disk will be kept, beware that a new volume has no format before his first attachment and so would not be mounted with this option)")
	flags.Bool("do-not-mount", false, "Prevent the volume to be mounted")

	return out
}

func volumeDetachCommand() *cobra.Command {
	out := &cobra.Command{
		Use:     "detach",
		Aliases: []string{"unbind"},
		Short:   "Detach a volume from a host",
		// ArgsUsage: "<Volume_name|Volume_ID> <Host_name|Host_ID>",
		RunE: func(c *cobra.Command, args []string) (ferr error) {
			defer fail.OnPanic(&ferr)
			logrus.Tracef("SafeScale command: %s %s with args '%s'", volumeCmdLabel, c.Name(), strings.Join(args, ", "))
			if len(args) != 2 {
				_ = c.Usage()
				return cli.FailureResponse(cli.ExitOnInvalidArgument("Missing mandatory argument <Volume_name> and/or <Host_name>."))
			}

			err := ClientSession.Volume.Detach(args[0], args[1], 0)
			if err != nil {
				err = fail.FromGRPCStatus(err)
				return cli.FailureResponse(cli.ExitOnRPC(strprocess.Capitalize(cmdline.DecorateTimeoutError(err, "unattach of volume", true).Error())))
			}

			return cli.SuccessResponse(nil)
		},
	}
	return out
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
		i = i + 1 // nolint
	}
	return speeds
}
