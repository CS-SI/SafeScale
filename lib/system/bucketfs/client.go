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

	"github.com/CS-SI/SafeScale/v21/lib/server/resources"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
)

// Client defines the structure of a Client object
type Client struct {
	host resources.Host
}

// NewClient creates a new NFS client instance
func NewClient(target resources.Host) (*Client, fail.Error) {
	if target == nil {
		return nil, fail.InvalidParameterCannotBeNilError("target")
	}

	return &Client{host: target}, nil
}

// Mount proceeds to the mount of a Bucket on Host
func (c *Client) Mount(ctx context.Context, description Description) fail.Error {
	if c == nil {
		return fail.InvalidInstanceError()
	}
	if c.host == nil {
		return fail.InvalidInstanceContentError("c.host", "cannot be nil")
	}
	if description.BucketName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("description.Name")
	}

	xerr := description.upload(ctx, c.host)
	if xerr != nil {
		return xerr
	}

	data := map[string]interface{}{
		"BucketName":       description.BucketName,
		"MountPoint":       description.MountPoint,
		"ConfigFile":       description.FilePath(),
		"OperatorUsername": description.OperatorUsername,
	}
	return executeScript(ctx, c.host, "bucket_mount.sh", data)
}

// Unmount a nfs share from NFS server
func (c *Client) Unmount(ctx context.Context, description Description) fail.Error {
	if c == nil {
		return fail.InvalidInstanceError()
	}
	if c.host == nil {
		return fail.InvalidInstanceContentError("c.host", "cannot be nil")
	}
	if description.BucketName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("description.Name")
	}

	data := map[string]interface{}{
		"MountPoint": description.MountPoint,
		"ConfigFile": description.FilePath(),
	}
	xerr := executeScript(ctx, c.host, "bucket_unmount.sh", data)
	if xerr != nil {
		return fail.Wrap(xerr, "error executing script to unmount Bucket")
	}

	return nil
}
