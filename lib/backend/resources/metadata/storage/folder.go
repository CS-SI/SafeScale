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

package storage

import (
	"context"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
)

const (
	OptionDisableCrypt = "do_not_crypt"
)

type (
	FolderCallback func([]byte) fail.Error

	Folder interface {
		AbsolutePath(path ...string) string                                                                             // returns the full path to reach the 'path'+'name' starting from the folder path
		Browse(ctx context.Context, path string, callback FolderCallback) fail.Error                                    // browses the content of a specific path in Metadata and executes 'callback' on each entry
		Delete(ctx context.Context, path string, name string) fail.Error                                                // removes metadata passed as parameter
		Job() jobapi.Job                                                                                                // returns the job of the folder
		Lookup(ctx context.Context, path string, name string) fail.Error                                                // tells if the object named 'name' is inside the metadata Folder
		Prefix() string                                                                                                 // returns the path of the Folder
		Read(ctx context.Context, path string, name string, callback FolderCallback, opts ...options.Option) fail.Error // loads the content of the object stored in metadata folder
		Service() iaasapi.Service                                                                                       // returns the current provider driver to use
		Write(ctx context.Context, path string, name string, content []byte, opts ...options.Option) fail.Error         // writes the content in storage, and check the write operation is committed
	}
)

// DisableCrypt asks to disable encryption
func DisableCrypt() options.Option {
	return func(o options.Options) fail.Error {
		return o.Store(OptionDisableCrypt, false)
	}
}