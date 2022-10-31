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

	"github.com/CS-SI/SafeScale/v22/lib/backend/common/scope"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type (
	FolderCallback func([]byte) fail.Error

	Folder interface {
		AbsolutePath(path ...string) string                                                                                        // returns the full path to reach the 'path'+'name' starting from the folder path
		Browse(ctx context.Context, path string, callback FolderCallback) fail.Error                                               // browses the content of a specific path in Metadata and executes 'callback' on each entry
		Delete(ctx context.Context, path string, name string) fail.Error                                                           // removes metadata passed as parameter
		Frame() *scope.Frame                                                                                                       // returns the scope of the folder
		Lookup(ctx context.Context, path string, name string) fail.Error                                                           // tells if the object named 'name' is inside the metadata Folder
		Prefix() string                                                                                                            // returns the path of the Folder
		Read(ctx context.Context, path string, name string, callback FolderCallback, options ...data.ImmutableKeyValue) fail.Error // loads the content of the object stored in metadata folder
		Service() iaasapi.Service                                                                                                  // returns the current provider driver to use
		Write(ctx context.Context, path string, name string, content []byte, options ...data.ImmutableKeyValue) fail.Error         // writes the content in storage, and check the write operation is committed
	}
)
