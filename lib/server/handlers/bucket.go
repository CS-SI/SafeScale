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
	"fmt"
	"regexp"

	"github.com/CS-SI/SafeScale/lib/server"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

//go:generate mockgen -destination=../mocks/mock_bucketapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers BucketAPI

// BucketAPI defines API to manipulate buckets
type BucketAPI interface {
	List() ([]string, error)
	Create(string) error
	Delete(string) error
	Inspect(string) (*resources.Bucket, error)
	Mount(string, string, string) error
	Unmount(string, string) error
}

// FIXME ROBUSTNESS All functions MUST propagate context

// BucketHandler bucket service
type BucketHandler struct {
	job server.Job
}

// NewBucketHandler creates a Bucket service
func NewBucketHandler(job server.Job) BucketAPI {
	return &BucketHandler{job: job}
}

// List retrieves all available buckets
func (handler *BucketHandler) List() (rv []string, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(handler.job.Task(), "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	rv, err = handler.job.Service().ListBuckets(objectstorage.RootPath)
	return rv, err
}

// Create a bucket
func (handler *BucketHandler) Create(name string) (err error) { // FIXME Unused ctx
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	if name == "" {
		return scerr.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(handler.job.Task(), "('"+name+"')", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	bucket, err := handler.job.Service().GetBucket(name)
	if err != nil {
		if err.Error() != "not found" {
			return err
		}
	}
	if bucket != nil {
		return resources.ResourceDuplicateError("bucket", name)
	}
	_, err = handler.job.Service().CreateBucket(name)
	if err != nil {
		return err
	}
	return nil
}

// Delete a bucket
func (handler *BucketHandler) Delete(name string) (err error) { // FIXME Unused ctx
	tracer := concurrency.NewTracer(handler.job.Task(), "('"+name+"')", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	err = handler.job.Service().DeleteBucket(name)
	if err != nil {
		return err
	}
	return nil
}

// Inspect a bucket
func (handler *BucketHandler) Inspect(name string) (mb *resources.Bucket, err error) {
	tracer := concurrency.NewTracer(handler.job.Task(), "('"+name+"')", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	b, err := handler.job.Service().GetBucket(name)
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
func (handler *BucketHandler) Mount(bucketName, hostName, path string) (err error) {
	if handler == nil {
		return scerr.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(handler.job.Task(), fmt.Sprintf("('%s', '%s', '%s')", bucketName, hostName, path), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	// Check bucket existence
	_, err = handler.job.Service().GetBucket(bucketName)
	if err != nil {
		return err
	}

	// Get Host ID
	hostHandler := NewHostHandler(handler.job)
	host, err := hostHandler.Inspect(hostName)
	if err != nil {
		return fmt.Errorf("no host found with name or id '%s'", hostName)
	}

	// Create mount point
	mountPoint := path
	if path == resources.DefaultBucketMountPoint {
		mountPoint = resources.DefaultBucketMountPoint + bucketName
	}

	authOpts, _ := handler.job.Service().GetAuthenticationOptions()
	authurlCfg, _ := authOpts.Config("AuthUrl")
	authurl, _ := authurlCfg.(string)
	authurl = regexp.MustCompile("https?:/+(.*)/.*").FindStringSubmatch(authurl)[1]
	tenantCfg, _ := authOpts.Config("TenantName")
	tenant, _ := tenantCfg.(string)
	loginCfg, _ := authOpts.Config("Login")
	login, _ := loginCfg.(string)
	passwordCfg, _ := authOpts.Config("Password")
	password, _ := passwordCfg.(string)
	regionCfg, _ := authOpts.Config("Region")
	region, _ := regionCfg.(string)

	objStorageProtocol := handler.job.Service().GetType()
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

	rerr := exec(handler.job, "mount_object_storage.sh", data, host.ID, handler.job.Service())
	return rerr
}

// Unmount a bucket
func (handler *BucketHandler) Unmount(bucketName, hostName string) (err error) {
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s')", bucketName, hostName), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	// Check bucket existence
	_, err = handler.Inspect(bucketName)
	if err != nil {
		if _, ok := err.(*scerr.ErrNotFound); ok {
			return err
		}
		return err
	}

	// Get Host ID
	hostHandler := NewHostHandler(handler.job)
	host, err := hostHandler.Inspect(hostName)
	if err != nil {
		if _, ok := err.(*scerr.ErrNotFound); ok {
			return err
		}
		return err
	}

	data := struct {
		Bucket string
	}{
		Bucket: bucketName,
	}

	rerr := exec(handler.job, "umount_object_storage.sh", data, host.ID, handler.job.Service())
	return rerr
}
