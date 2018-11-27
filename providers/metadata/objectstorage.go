/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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
	"os"
	"strings"
)

// BuildMetadataBucketName builds the name of the bucket/container that will store metadata
// id must be a unique identifier of the tenant (not the tenant itself, probability of having same
// name for 2 different customers isn't zero; this can be domain or project name)
func BuildMetadataBucketName(id string) string {
	name := BucketNamePrefix + "-" + id
	if suffix, ok := os.LookupEnv("SAFESCALE_METADATA_SUFFIX"); ok {
		name += "." + suffix
	}
	return strings.ToLower(name)
}
