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
	"regexp"

	"github.com/CS-SI/SafeScale/lib/server"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	hostfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/host"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

//go:generate mockgen -destination=../mocks/mock_bucketapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers BucketHandler

// BucketHandler defines interface to manipulate buckets
type BucketHandler interface {
	List() ([]string, error)
	Create(string) error
	Delete(string) error
	Inspect(string) (*abstract.Bucket, error)
	Mount(string, string, string) error
	Unmount(string, string) error
}

// bucketHandler bucket service
type bucketHandler struct {
	job server.Job
}

// NewBucketHandler creates a Bucket service
func NewBucketHandler(job server.Job) BucketHandler {
	return &bucketHandler{job: job}
}

// List retrieves all available buckets
func (handler *bucketHandler) List() (rv []string, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}

	tracer := concurrency.NewTracer(handler.job.SafeGetTask(), true, "").WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	rv, err = handler.job.SafeGetService().ListBuckets(objectstorage.RootPath)
	return rv, err
}

// Create a bucket
func (handler *bucketHandler) Create(name string) (err error) { // FIXME Unused ctx
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	if name == "" {
		return scerr.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(handler.job.SafeGetTask(), debug.IfTrace("handlers.bucket"), "('"+name+"')").WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	svc := handler.job.SafeGetService()
	bucket, err := svc.GetBucket(name)
	if err != nil {
		if err.Error() != "not found" {
			return err
		}
	}
	if bucket != nil {
		return abstract.ResourceDuplicateError("bucket", name)
	}
	_, err = svc.CreateBucket(name)
	if err != nil {
		return err
	}
	return nil
}

// Delete a bucket
func (handler *bucketHandler) Delete(name string) (err error) {
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	if name == "" {
		return scerr.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(handler.job.SafeGetTask(), debug.IfTrace("handlers.bucket"), "('"+name+"')").WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	err = handler.job.SafeGetService().DeleteBucket(name)
	if err != nil {
		return err
	}
	return nil
}

// Inspect a bucket
func (handler *bucketHandler) Inspect(name string) (mb *abstract.Bucket, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(handler.job.SafeGetTask(), debug.IfTrace("handlers.bucket"), "('"+name+"')").WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	b, err := handler.job.SafeGetService().GetBucket(name)
	if err != nil {
		if err.Error() == "not found" {
			return nil, abstract.ResourceNotFoundError("bucket", name)
		}
		return nil, err
	}
	mb = &abstract.Bucket{
		Name: b.SafeGetName(),
	}
	return mb, nil
}

// Mount a bucket on an host on the given mount point
func (handler *bucketHandler) Mount(bucketName, hostName, path string) (err error) {
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	if bucketName == "" {
		return scerr.InvalidParameterError("bucketName", "cannot be empty string")
	}
	if hostName == "" {
		return scerr.InvalidParameterError("hostName", "cannot be empty string")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.IfTrace("handlers.bucket"), "('%s', '%s', '%s')", bucketName, hostName, path).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	// Check bucket existence
	_, err = handler.job.SafeGetService().GetBucket(bucketName)
	if err != nil {
		return err
	}

	// Get Host ID
	svc := handler.job.SafeGetService()
	host, err := hostfactory.Load(task, svc, hostName)
	if err != nil {
		return scerr.NotFoundError("no host found with name or id '%s'", hostName)
	}

	// Create mount point
	mountPoint := path
	if path == "" || path == abstract.DefaultBucketMountPoint {
		mountPoint = abstract.DefaultBucketMountPoint + bucketName
	}

	authOpts, _ := svc.GetAuthenticationOptions()
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

	objStorageProtocol := handler.job.SafeGetService().SafeGetObjectStorageProtocol()
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

	rerr := exec(handler.job, "mount_object_storage.sh", data, host.SafeGetID(), svc)
	return rerr
}

// Unmount a bucket
func (handler *bucketHandler) Unmount(bucketName, hostName string) (err error) {
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	if bucketName == "" {
		return scerr.InvalidParameterError("bucketName", "cannot be empty string")
	}
	if hostName == "" {
		return scerr.InvalidParameterError("hostName", "cannot be empty string")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.IfTrace("handlers.bucket"), "('%s', '%s')", bucketName, hostName).WithStopwatch().Entering()
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
	svc := handler.job.SafeGetService()
	host, err := hostfactory.Load(task, svc, hostName)
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

	rerr := exec(handler.job, "umount_object_storage.sh", data, host.SafeGetID(), svc)
	return rerr
}
