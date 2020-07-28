/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package resources

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// Callback describes the function prototype to use to inspect metadata
type Callback = func(data.Clonable, *serialize.JSONProperties) fail.Error

// Metadata contains the core functions of a persistent object
type Metadata interface {
	Serialize(concurrency.Task) ([]byte, fail.Error)
	Deserialize(concurrency.Task, []byte) fail.Error

	GetService() iaas.Service                                                            // GetService returns the iaas.Service used
	Inspect(task concurrency.Task, callback Callback) fail.Error                         // Inspect protects the data for shared read
	Alter(task concurrency.Task, callback Callback) fail.Error                           // Alter protects the data for exclusive write
	Carry(task concurrency.Task, clonable data.Clonable) fail.Error                      // Carry links metadata with real data
	Read(task concurrency.Task, ref string) fail.Error                                   // Read gets the data from Object Storage
	Reload(task concurrency.Task) fail.Error                                             // reload Reloads the metadata from the Object Storage, overriding what is in the object
	BrowseFolder(task concurrency.Task, callback func(buf []byte) fail.Error) fail.Error // Browse walks through host folder and executes a callback for each entries
	Delete(task concurrency.Task) fail.Error                                             // Delete deletes the matadata
}
