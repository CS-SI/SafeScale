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

	"github.com/CS-SI/SafeScale/iaas"
	"github.com/CS-SI/SafeScale/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/iaas/resources"
)

//go:generate mockgen -destination=../mocks/mock_bucketapi.go -package=mocks github.com/CS-SI/SafeScale/broker/server/handlers BucketAPI

// BucketAPI defines API to manipulate buckets
type BucketAPI interface {
	List(context.Context) ([]string, error)
	Create(context.Context, string) error
	Delete(context.Context, string) error
	Inspect(context.Context, string) (*resources.Bucket, error)
	Mount(context.Context, string, string, string) error
	Unmount(context.Context, string, string) error
}

// BucketHandler bucket service
type BucketHandler struct {
	service *iaas.Service
}

// NewBucketHandler creates a Bucket service
func NewBucketHandler(svc *iaas.Service) BucketAPI {
	return &BucketHandler{service: svc}
}

// List retrieves all available buckets
func (handler *BucketHandler) List(ctx context.Context) ([]string, error) {
	rv, err := handler.service.ListBuckets(objectstorage.RootPath)
	return rv, infraErr(err)
}

// Create a bucket
func (handler *BucketHandler) Create(ctx context.Context, name string) error {
	bucket, err := handler.service.GetBucket(name)
	if err != nil {
		if err.Error() != "not found" {
			return infraErrf(err, "failed to search of bucket '%s' already exists", name)
		}
	}
	if bucket != nil {
		return logicErr(resources.ResourceDuplicateError("bucket", name))
	}
	_, err = handler.service.CreateBucket(name)
	if err != nil {
		return infraErrf(err, "failed to create bucket '%s'", name)
	}
	return nil
}

// Delete a bucket
func (handler *BucketHandler) Delete(ctx context.Context, name string) error {
	err := handler.service.DeleteBucket(name)
	if err != nil {
		return infraErrf(err, "failed to delete bucket '%s'", name)
	}
	return nil
}

// Inspect a bucket
func (handler *BucketHandler) Inspect(ctx context.Context, name string) (*resources.Bucket, error) {
	b, err := handler.service.GetBucket(name)
	if err != nil {
		if err.Error() == "not found" {
			return nil, logicErr(resources.ResourceNotFoundError("bucket", name))
		}
		return nil, infraErrf(err, "failed to inspect bucket '%s'", name)
	}
	mb := resources.Bucket{
		Name: b.GetName(),
	}
	return &mb, nil
}

// Mount a bucket on an host on the given mount point
func (handler *BucketHandler) Mount(ctx context.Context, bucketName, hostName, path string) error {
	// Check bucket existence
	_, err := handler.service.GetBucket(bucketName)
	if err != nil {
		return infraErr(err)
	}

	// Get Host ID
	hostHandler := NewHostHandler(handler.service)
	host, err := hostHandler.Inspect(ctx, hostName)
	if err != nil {
		return logicErr(fmt.Errorf("no host found with name or id '%s'", hostName))
	}

	// Create mount point
	mountPoint := path
	if path == resources.DefaultBucketMountPoint {
		mountPoint = resources.DefaultBucketMountPoint + bucketName
	}

	authOpts, _ := handler.service.GetAuthOpts()
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

	objStorageProtocol := handler.service.GetType()
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

	rerr := exec(ctx, "mount_object_storage.sh", data, host.ID, handler.service)
	return logicErr(rerr)
}

// Unmount a bucket
func (handler *BucketHandler) Unmount(ctx context.Context, bucketName, hostName string) error {
	// Check bucket existence
	_, err := handler.Inspect(ctx, bucketName)
	if err != nil {
		if _, ok := err.(resources.ErrResourceNotFound); ok {
			return err
		}
		return infraErr(err)
	}

	// Get Host ID
	hostHandler := NewHostHandler(handler.service)
	host, err := hostHandler.Inspect(ctx, hostName)
	if err != nil {
		if _, ok := err.(resources.ErrResourceNotFound); ok {
			return err
		}
		return infraErrf(err, "failed to get host '%s':", hostName)
	}

	data := struct {
		Bucket string
	}{
		Bucket: bucketName,
	}

	rerr := exec(ctx, "umount_object_storage.sh", data, host.ID, handler.service)
	return infraErr(rerr)
}
