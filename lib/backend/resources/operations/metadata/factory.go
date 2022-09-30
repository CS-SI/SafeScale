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

package metadata

import (
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/metadata/storage"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/metadata/storage/bucket"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/metadata/storage/consul"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

const (
	MethodObjectStorage = "objectstorage"
	MethodConsul        = "consul"
)

// NewFolder creates a Folder corresponding to the method wanted
func NewFolder(method string, svc iaasapi.Service, path string) (storage.Folder, fail.Error) {
	switch method {
	case MethodObjectStorage:
		return bucket.NewFolder(svc, path)
	case MethodConsul:
		return consul.NewFolder(svc, path)
	default:
		return nil, fail.InvalidParameterError("method", "'%s' method is unsupported", method)
	}
}
