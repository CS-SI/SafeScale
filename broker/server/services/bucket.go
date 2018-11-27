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

package services

import (
	"fmt"
	"regexp"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/objectstorage"
)

//go:generate mockgen -destination=../mocks/mock_bucketapi.go -package=mocks github.com/CS-SI/SafeScale/broker/server/services BucketAPI

// BucketAPI defines API to manipulate buckets
type BucketAPI interface {
	List() ([]string, error)
	Create(string) error
	Delete(string) error
	Inspect(string) (*model.Bucket, error)
	Mount(string, string, string) error
	Unmount(string, string) error
}

// BucketService bucket service
type BucketService struct {
	provider *providers.Service
}

// NewBucketService creates a Bucket service
func NewBucketService(api *providers.Service) BucketAPI {
	return &BucketService{provider: api}
}

// List retrieves all available buckets
func (svc *BucketService) List() ([]string, error) {
	return svc.provider.ObjectStorage.ListBuckets(objectstorage.RootPath)
}

// Create a bucket
func (svc *BucketService) Create(name string) error {
	bucket, err := svc.provider.ObjectStorage.GetBucket(name)
	if err != nil {
		if err.Error() != "not found" {
			return errors.Wrap(err, "failed to search of bucket '%s' already exists")
		}
	}
	if bucket != nil {
		return model.ResourceAlreadyExistsError("bucket", name)
	}
	_, err = svc.provider.ObjectStorage.CreateBucket(name)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to create bucket '%s'", name))
	}
	return nil
}

// Delete a bucket
func (svc *BucketService) Delete(name string) error {
	err := svc.provider.ObjectStorage.DeleteBucket(name)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to delete bucket '%s'", name))
	}
	return nil
}

// Inspect a bucket
func (svc *BucketService) Inspect(name string) (*model.Bucket, error) {
	b, err := svc.provider.ObjectStorage.GetBucket(name)
	if err != nil {
		if err.Error() == "not found" {
			return nil, model.ResourceNotFoundError("bucket", name)
		}
		return nil, errors.Wrap(err, fmt.Sprintf("failed to inspect bucket '%s'", name))
	}
	mb := model.Bucket{
		Name: b.GetName(),
	}
	return &mb, nil
}

// Mount a bucket on an host on the given mount point
func (svc *BucketService) Mount(bucketName, hostName, path string) error {
	// Check bucket existence
	_, err := svc.provider.ObjectStorage.GetBucket(bucketName)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return tbr
	}

	// Get Host ID
	hostService := NewHostService(svc.provider)
	host, err := hostService.Get(hostName)
	if err != nil {
		return fmt.Errorf("no host found with name or id '%s'", hostName)
	}

	// Create mount point
	mountPoint := path
	if path == model.DefaultBucketMountPoint {
		mountPoint = model.DefaultBucketMountPoint + bucketName
	}

	authOpts, _ := svc.provider.GetAuthOpts()
	authurlCfg, _ := authOpts.Config("AuthUrl")
	authurl := authurlCfg.(string)
	authurl = regexp.MustCompile("https?:/+(.*)/.*").FindStringSubmatch(authurl)[1]
	tenantCfg, _ := authOpts.Config("TenantName")
	tenant := tenantCfg.(string)
	loginCfg, _ := authOpts.Config("Login")
	login := loginCfg.(string)
	passwordCfg, _ := authOpts.Config("Password")
	password := passwordCfg.(string)
	regionCfg, _ := authOpts.Config("Region")
	region := regionCfg.(string)

	objStorageProtocol := svc.provider.ObjectStorage.GetType()
	if objStorageProtocol == "swift" {
		objStorageProtocol = "swiftks"
	}

	data := struct {
		Bucket     string
		Tenant     string
		Login      string
		Password   string
		AuthURL    string
		Region     string
		MountPoint string
		Protocol   string
	}{
		Bucket:     bucketName,
		Tenant:     tenant,
		Login:      login,
		Password:   password,
		AuthURL:    authurl,
		Region:     region,
		MountPoint: mountPoint,
		Protocol:   objStorageProtocol,
	}

	return exec("mount_object_storage.sh", data, host.ID, svc.provider)
}

// Unmount a bucket
func (svc *BucketService) Unmount(bucketName, hostName string) error {
	// Check bucket existence
	_, err := svc.Inspect(bucketName)
	if err != nil {
		switch err.(type) {
		case model.ErrResourceNotFound:
			return err
		default:
			tbr := errors.Wrap(err, "")
			log.Errorf("%+v", tbr)
			return tbr
		}
	}

	// Get Host ID
	hostService := NewHostService(svc.provider)
	host, err := hostService.Get(hostName)
	if err != nil {
		switch err.(type) {
		case model.ErrResourceNotFound:
			return err
		default:
			return errors.Wrap(err, fmt.Sprintf("failed to get host '%s':", hostName))
		}
	}

	data := struct {
		Bucket string
	}{
		Bucket: bucketName,
	}

	return exec("umount_object_storage.sh", data, host.ID, svc.provider)
}
