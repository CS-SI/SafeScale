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

package handlers

import (
	"context"
	"fmt"
	"regexp"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/objectstorage"
)

//go:generate mockgen -destination=../mocks/mock_bucketapi.go -package=mocks github.com/CS-SI/SafeScale/broker/server/handlers BucketAPI

// BucketAPI defines API to manipulate buckets
type BucketAPI interface {
	List(context.Context) ([]string, error)
	Create(context.Context, string) error
	Delete(context.Context, string) error
	Inspect(context.Context, string) (*model.Bucket, error)
	Mount(context.Context, string, string, string) error
	Unmount(context.Context, string, string) error
}

// BucketHandler bucket service
type BucketHandler struct {
	provider *providers.Service
}

// NewBucketHandler creates a Bucket service
func NewBucketHandler(api *providers.Service) BucketAPI {
	return &BucketHandler{provider: api}
}

// List retrieves all available buckets
func (svc *BucketHandler) List(ctx context.Context) ([]string, error) {
	rv, err := svc.provider.ObjectStorage.ListBuckets(objectstorage.RootPath)
	return rv, infraErr(err)
}

// Create a bucket
func (svc *BucketHandler) Create(ctx context.Context, name string) error {
	bucket, err := svc.provider.ObjectStorage.GetBucket(name)
	if err != nil {
		if err.Error() != "not found" {
			return infraErrf(err, "failed to search of bucket '%s' already exists", name)
		}
	}
	if bucket != nil {
		return logicErr(model.ResourceAlreadyExistsError("bucket", name))
	}
	_, err = svc.provider.ObjectStorage.CreateBucket(name)
	if err != nil {
		return infraErrf(err, "failed to create bucket '%s'", name)
	}
	return nil
}

// Delete a bucket
func (svc *BucketHandler) Delete(ctx context.Context, name string) error {
	err := svc.provider.ObjectStorage.DeleteBucket(name)
	if err != nil {
		return infraErrf(err, "failed to delete bucket '%s'", name)
	}
	return nil
}

// Inspect a bucket
func (svc *BucketHandler) Inspect(ctx context.Context, name string) (*model.Bucket, error) {
	b, err := svc.provider.ObjectStorage.GetBucket(name)
	if err != nil {
		if err.Error() == "not found" {
			return nil, logicErr(model.ResourceNotFoundError("bucket", name))
		}
		return nil, infraErrf(err, "failed to inspect bucket '%s'", name)
	}
	mb := model.Bucket{
		Name: b.GetName(),
	}
	return &mb, nil
}

// Mount a bucket on an host on the given mount point
func (svc *BucketHandler) Mount(ctx context.Context, bucketName, hostName, path string) error {
	// Check bucket existence
	_, err := svc.provider.ObjectStorage.GetBucket(bucketName)
	if err != nil {
		return infraErr(err)
	}

	// Get Host ID
	hostHandler := NewHostHandler(svc.provider)
	host, err := hostHandler.Inspect(ctx, hostName)
	if err != nil {
		return logicErr(fmt.Errorf("no host found with name or id '%s'", hostName))
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

	rerr := exec(ctx, "mount_object_storage.sh", data, host.ID, svc.provider)
	return logicErr(rerr)
}

// Unmount a bucket
func (svc *BucketHandler) Unmount(ctx context.Context, bucketName, hostName string) error {
	// Check bucket existence
	_, err := svc.Inspect(ctx, bucketName)
	if err != nil {
		switch err.(type) {
		case model.ErrResourceNotFound:
			return infraErr(err)
		default:
			return infraErr(err)
		}
	}

	// Get Host ID
	hostHandler := NewHostHandler(svc.provider)
	host, err := hostHandler.Inspect(ctx, hostName)
	if err != nil {
		switch err.(type) {
		case model.ErrResourceNotFound:
			return infraErr(err)
		default:
			return infraErrf(err, "failed to get host '%s':", hostName)
		}
	}

	data := struct {
		Bucket string
	}{
		Bucket: bucketName,
	}

	rerr := exec(ctx, "umount_object_storage.sh", data, host.ID, svc.provider)
	return infraErr(rerr)
}
