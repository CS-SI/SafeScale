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

package handlers

import (
	"context"
	"fmt"
	"regexp"

	"github.com/graymeta/stow"

	"github.com/CS-SI/SafeScale/lib/utils/debug"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

//go:generate mockgen -destination=../mocks/mock_bucketapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers BucketAPI

// BucketAPI defines API to manipulate buckets
type BucketAPI interface {
	List(context.Context) ([]string, error)
	Create(context.Context, string) error
	Delete(context.Context, string) error
	Destroy(context.Context, string) error
	Inspect(context.Context, string) (*abstract.Bucket, error)
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
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	rv, err = handler.service.ListBuckets(objectstorage.RootPath)
	return rv, err
}

// Create a bucket
func (handler *BucketHandler) Create(ctx context.Context, name string) (err error) {
	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, "('"+name+"')", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	bucket, err := handler.service.GetBucket(name)
	if err != nil {
		if err != stow.ErrNotFound { // FIXME: Remove stow dependency
			return err
		}
	}
	if bucket != nil {
		return abstract.ResourceDuplicateError("bucket", name)
	}
	_, err = handler.service.CreateBucket(name)
	if err != nil {
		return err
	}
	return nil
}

// Destroy a bucket, clear then delete
func (handler *BucketHandler) Destroy(ctx context.Context, name string) (err error) {
	tracer := debug.NewTracer(nil, "('"+name+"')", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	err = handler.service.ClearBucket(name, "/", "")
	if err != nil {
		return err
	}

	err = handler.service.DeleteBucket(name)
	if err != nil {
		return err
	}
	return nil
}

// Delete a bucket
func (handler *BucketHandler) Delete(ctx context.Context, name string) (err error) {
	tracer := debug.NewTracer(nil, "('"+name+"')", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	err = handler.service.DeleteBucket(name)
	if err != nil {
		return err
	}
	return nil
}

// Inspect a bucket
func (handler *BucketHandler) Inspect(ctx context.Context, name string) (mb *abstract.Bucket, err error) {
	tracer := debug.NewTracer(nil, "('"+name+"')", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	b, err := handler.service.GetBucket(name)
	if err != nil {
		if err == stow.ErrNotFound { // FIXME: Remove stow dependency
			return nil, abstract.ResourceNotFoundError("bucket", name)
		}

		return nil, err
	}

	bucketName, err := b.GetName()
	if err != nil {
		return nil, err
	}

	mb = &abstract.Bucket{
		Name: bucketName,
	}
	return mb, nil
}

// Mount a bucket on an host on the given mount point
func (handler *BucketHandler) Mount(ctx context.Context, bucketName, hostName, path string) (err error) {
	tracer := debug.NewTracer(
		nil, fmt.Sprintf("('%s', '%s', '%s')", bucketName, hostName, path), true,
	).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

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
	if path == abstract.DefaultBucketMountPoint {
		mountPoint = abstract.DefaultBucketMountPoint + bucketName
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
	tracer := debug.NewTracer(nil, fmt.Sprintf("('%s', '%s')", bucketName, hostName), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	// Check bucket existence
	_, err = handler.Inspect(ctx, bucketName)
	if err != nil {
		if _, ok := err.(fail.ErrNotFound); ok {
			return err
		}
		return err
	}

	// Get Host ID
	hostHandler := NewHostHandler(handler.service)
	host, err := hostHandler.Inspect(ctx, hostName)
	if err != nil {
		if _, ok := err.(fail.ErrNotFound); ok {
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
