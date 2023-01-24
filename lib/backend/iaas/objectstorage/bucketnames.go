/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

package objectstorage

import (
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"os"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

const (
	// BucketNamePrefix is the beginning of the name of the bucket for Metadata
	BucketNamePrefix = "0.safescale"
)

const (
	maxBucketNameLength = 63
	suffixEnvName       = "SAFESCALE_METADATA_SUFFIX"
)

// BuildMetadataBucketName builds the name of the bucket/stowContainer that will store metadata
func BuildMetadataBucketName(driver, region, domain, project string) (name string, ferr fail.Error) {
	hash := fnv.New128a()
	sig := strings.ToLower(fmt.Sprintf("%s-%s-%s-%s", driver, region, domain, project))
	_, herr := hash.Write([]byte(sig))
	if herr != nil {
		return "", fail.Wrap(herr)
	}
	hashed := hex.EncodeToString(hash.Sum(nil))
	name = BucketNamePrefix + "-" + hashed

	nameLen := len(name)
	if suffix, ok := os.LookupEnv(suffixEnvName); ok && suffix != "" {
		name += "." + suffix
		if len(name) > maxBucketNameLength {
			return "", fail.OverflowError(nil, maxBucketNameLength, "suffix '%s' is too long, max allowed: %d characters", suffix, maxBucketNameLength-nameLen-1)
		}
	}
	if len(name) > maxBucketNameLength {
		return "", fail.OverflowError(nil, maxBucketNameLength, "name '%s' is too long, max allowed: %d characters", name, maxBucketNameLength-1)
	}

	name = strings.ToLower(name)

	return name, nil
}
