/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
	"os"
	"strings"

	"hash/fnv"
)

const (
	maxBucketNameLength = 63
	// bucketNamePrefix is the begining of the name of the bucket for Metadata
	bucketNamePrefix = "0.safescale"
	storageSuffix    = ".storage"
	suffixEnvName    = "SAFESCALE_METADATA_SUFFIX"
)

// BuildMetadataBucketName builds the name of the bucket/container that will store metadata
func BuildMetadataBucketName(driver, region, domain, project string) (string, error) {
	hash := fnv.New128a()
	sig := strings.ToLower(fmt.Sprintf("%s-%s-%s-%s", driver, region, domain, project))
	_, _ = hash.Write([]byte(sig))
	hashed := hex.EncodeToString(hash.Sum(nil))
	name := bucketNamePrefix + "-" + hashed
	nameLen := len(name)
	if suffix, ok := os.LookupEnv(suffixEnvName); ok {
		name += "." + suffix
		if len(name) > maxBucketNameLength {
			return "", fmt.Errorf("Suffix is too long, max allowed: %d characters", maxBucketNameLength-nameLen-1)
		}
	}
	return strings.ToLower(name), nil
}

// BuildStorageBucketName builds the name of the bucket/container that will store metadata
func BuildStorageBucketName(driver, region, domain, project string) (string, error) {
	hash := fnv.New128a()
	sig := strings.ToLower(fmt.Sprintf("%s-%s-%s-%s", driver, region, domain, project))
	_, _ = hash.Write([]byte(sig))
	hashed := hex.EncodeToString(hash.Sum(nil))
	name := bucketNamePrefix + "-" + hashed + storageSuffix
	//TODO-AJ : user specific sorages?
	return strings.ToLower(name), nil
}
