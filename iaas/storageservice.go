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

package iaas

import (
	"fmt"

	"github.com/CS-SI/SafeScale/iaas/objectstorage"
)

//StorageServices ...
type StorageServices struct {
	buckets []objectstorage.Bucket
}

//NewStorageService ...
func NewStorageService() StorageServices {
	return StorageServices{}
}

//RegisterStorage ...
func (sts *StorageServices) RegisterStorage(tenantName string) error {
	tenants, err := getTenantsFromCfg()
	if err != nil {
		return err
	}
	var tenant map[string]interface{}
	for _, t := range tenants {
		tenantTmp := t.(map[string]interface{})
		name, found := tenantTmp["name"].(string)
		_, found2 := tenantTmp["objectstorage"]
		if found && found2 && name == tenantName {
			tenant = tenantTmp
			break
		}
	}
	if tenant == nil {
		return fmt.Errorf("Tenant %s not found, or is not matching requirements", tenantName)
	}

	objectStorageConfig, err := initObjectStorageLocationConfig(tenant)
	if err != nil {
		return err
	}
	objectStorageLocation, err := objectstorage.NewLocation(objectStorageConfig)
	if err != nil {
		return fmt.Errorf("Error connecting to Object Storage Location: %s", err.Error())
	}

	bucketName, err := objectstorage.BuildStorageBucketName(tenantName, objectStorageConfig.Region, objectStorageConfig.Domain, objectStorageConfig.Tenant)
	if err != nil {
		return fmt.Errorf("Error building the bucketName : %s", err.Error())
	}

	exists, err := objectStorageLocation.FindBucket(bucketName)
	if err != nil {
		return fmt.Errorf("Error finding bucket '%s' : %s", bucketName, err.Error())
	}
	var bucket objectstorage.Bucket
	if !exists {
		bucket, err = objectStorageLocation.CreateBucket(bucketName)
		if err != nil {
			return fmt.Errorf("Error creating bucket '%s' : %s", bucketName, err.Error())
		}
	} else {
		bucket, err = objectStorageLocation.GetBucket(bucketName)
		if err != nil {
			return fmt.Errorf("Error getting bucket '%s' : %s", bucketName, err.Error())
		}
	}

	sts.buckets = append(sts.buckets, bucket)

	return nil
}

//GetBuckets ...
func (sts *StorageServices) GetBuckets() []objectstorage.Bucket {
	return sts.buckets
}
