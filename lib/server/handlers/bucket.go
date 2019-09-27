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

package handlers

import (
	"context"
	"fmt"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/sirupsen/logrus"
	"regexp"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
)

//go:generate mockgen -destination=../mocks/mock_bucketapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers BucketAPI

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
	service iaas.Service
}

// NewBucketHandler creates a Bucket service
func NewBucketHandler(svc iaas.Service) BucketAPI {
	return &BucketHandler{service: svc}
}

// List retrieves all available buckets
func (handler *BucketHandler) List(ctx context.Context) (rv []string, err error) {
	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.handlers.BucketHandler::List() called"), &err, logrus.TraceLevel)()

	rv, err = handler.service.ListBuckets(objectstorage.RootPath)
	return rv, err
}

// Create a bucket
func (handler *BucketHandler) Create(ctx context.Context, name string) (err error) {
	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.handlers.BucketHandler::Create() called"), &err, logrus.TraceLevel)()
	bucket, err := handler.service.GetBucket(name)
	if err != nil {
		if err.Error() != "not found" {
			return err
		}
	}
	if bucket != nil {
		return resources.ResourceDuplicateError("bucket", name)
	}
	_, err = handler.service.CreateBucket(name)
	if err != nil {
		return err
	}
	return nil
}

// Delete a bucket
func (handler *BucketHandler) Delete(ctx context.Context, name string) (err error) {
	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.handlers.BucketHandler::Create() called"), &err, logrus.TraceLevel)()
	err = handler.service.DeleteBucket(name)
	if err != nil {
		return err
	}
	return nil
}

// Inspect a bucket
func (handler *BucketHandler) Inspect(ctx context.Context, name string) (mb *resources.Bucket, err error) {
	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.handlers.BucketHandler::Inspect() called"), &err, logrus.TraceLevel)()

	b, err := handler.service.GetBucket(name)
	if err != nil {
		if err.Error() == "not found" {
			return nil, resources.ResourceNotFoundError("bucket", name)
		}
		return nil, err
	}
	mb = &resources.Bucket{
		Name: b.GetName(),
	}
	return mb, nil
}

// Mount a bucket on an host on the given mount point
func (handler *BucketHandler) Mount(ctx context.Context, bucketName, hostName, path string) (err error) {
	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.handlers.BucketHandler::Mount() called"), &err, logrus.TraceLevel)()

	// Check bucket existence
	_, err = handler.service.GetBucket(bucketName)
	if err != nil {
		return err
	}

	// Get Host ID
	hostHandler := NewHostHandler(handler.service)
	host, err := hostHandler.Inspect(ctx, hostName)
	if err != nil {
		return fmt.Errorf("no host found with name or id '%s'", hostName)
	}

	// Create mount point
	mountPoint := path
	if path == resources.DefaultBucketMountPoint {
		mountPoint = resources.DefaultBucketMountPoint + bucketName
	}

	authOpts, _ := handler.service.GetAuthenticationOptions()
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
	return rerr
}

// Unmount a bucket
func (handler *BucketHandler) Unmount(ctx context.Context, bucketName, hostName string) (err error) {
	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.handlers.BucketHandler::Unmount() called"), &err, logrus.TraceLevel)()
	// Check bucket existence
	_, err = handler.Inspect(ctx, bucketName)
	if err != nil {
		if _, ok := err.(utils.ErrNotFound); ok {
			return err
		}
		return err
	}

	// Get Host ID
	hostHandler := NewHostHandler(handler.service)
	host, err := hostHandler.Inspect(ctx, hostName)
	if err != nil {
		if _, ok := err.(utils.ErrNotFound); ok {
			return err
		}
		return err
	}

	data := struct {
		Bucket string
	}{
		Bucket: bucketName,
	}

	rerr := exec(ctx, "umount_object_storage.sh", data, host.ID, handler.service)
	return rerr
}
