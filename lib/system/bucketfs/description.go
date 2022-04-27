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
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package bucketfs

import (
	"context"
	"os"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/system"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// Description contains the configuration for bucket mount
type Description struct {
	BucketName       string
	ProjectName      string
	Username         string
	Password         string
	AuthVersion      string
	AuthURL          string
	Endpoint         string
	Region           string
	MountPoint       string
	Protocol         string
	OperatorUsername string
}

// Upload uploads configuration file to remote host
func (desc *Description) upload(ctx context.Context, host resources.Host) fail.Error {
	f, xerr := desc.createConfigurationFile()
	if xerr != nil {
		return xerr
	}

	// cleanup local temporary file
	defer func() {
		_ = os.Remove(f.Name())
	}()

	svc := host.Service()
	timings, xerr := svc.Timings()
	if xerr != nil {
		return xerr
	}

	svcConf, xerr := svc.GetConfigurationOptions()
	if xerr != nil {
		return xerr
	}

	if anon, ok := svcConf.Get("OperatorUsername"); ok {
		desc.OperatorUsername, ok = anon.(string)
		if !ok {
			return fail.NewError("OperatorUsername must be a string, it's not: %v", anon)
		}
	} else {
		desc.OperatorUsername = abstract.DefaultUser
	}
	owner := desc.OperatorUsername + ":" + desc.OperatorUsername
	target := desc.FilePath()
	retcode, stdout, stderr, xerr := host.Push(ctx, f.Name(), target, owner, "0600", timings.ExecutionTimeout())
	if xerr != nil {
		return fail.Wrap(xerr, "failed to upload rclone configuration file")
	}
	if retcode != 0 {
		xerr = fail.ExecutionError(xerr, "failed to copy rclone configuration file: %s, %s", stdout, stderr)
		xerr.Annotate("retcode", retcode).Annotate("stdout", stdout).Annotate("stderr", stderr)
		return xerr
	}

	return nil
}

// FilePath returns the absolute path of the rclone configuration file on the remote server
func (desc Description) FilePath() string {
	return utils.EtcFolder + "/rclone/" + desc.BucketName + ".conf"
}

// createConfigurationFile creates the content of the needed rclone configuration file and put it in a
// temporary file locally, ready to be pushed on remote server
func (desc Description) createConfigurationFile() (*os.File, fail.Error) {
	var content string

	// Build content of configuration file from content of desc
	var templateName string
	switch desc.Protocol {
	case "swift":
		templateName = "rclone-swift.conf"
	case "s3":
		templateName = "rclone-s3.conf"
	case "google":
		templateName = "rclone-google.conf"                                                               // nolint
		return nil, fail.NotImplementedError("mount of Google Object Storage Bucket not yet implemented") // FIXME: Technical debt
	default:
		return nil, fail.InvalidRequestError("unsupported Object Storage protocol '%s'", desc.Protocol)
	}

	content, xerr := realizeTemplate(templateName, &desc)
	if xerr != nil {
		return nil, xerr
	}

	// build temporary file
	f, xerr := system.CreateTempFileFromString(content, 0666) // nolint
	if xerr != nil {
		return nil, xerr
	}

	return f, nil
}
