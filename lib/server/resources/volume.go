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
	"github.com/CS-SI/SafeScale/lib/server/resources/abstracts"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
)

// Volume links Object Storage folder and Volumes
type Volume interface {
	Metadata
	data.Identifyable

	Browse(task concurrency.Task, callback func(*abstracts.Volume) error) error           // Browse walks through all the metadata objects in network
	Create(task concurrency.Task, req abstracts.VolumeRequest) error                      // Create a volume
	Attach(task concurrency.Task, host Host, path, format string, doNotFormat bool) error // Attach a volume to an host
	Detach(task concurrency.Task, host Host) error                                        // Detach detach the volume identified by ref, ref can be the name or the id
}
