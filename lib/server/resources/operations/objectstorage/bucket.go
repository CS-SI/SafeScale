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

package objectstorage

import (
	"context"
	"fmt"
	"regexp"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// bucket describes a Bucket and satisfies interface resources.Bucket
type bucket struct {
	svc iaas.Service

	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Host       string `json:"host,omitempty"`
	MountPoint string `json:"mountPoint,omitempty"`
	// NbItems    int    `json:"nbitems,omitempty"`
}

// New intanciantes bucket struct
func New(svc iaas.Service) (*bucket, error) {
	if svc == nil {
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}
	return &bucket{svc: svc}, nil
}

// Load instanciantes a bucket struct and fill it with Provider metadata of Object Storage Bucket
func Load(svc iaas.Service, name string) (_ *bucket, err error) {
	if svc == nil {
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(nil, true, "('"+name+"')").WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	b, err := New(svc)
	if err != nil {
		return nil, err
	}

	pb, err := svc.GetBucket(name)
	if err != nil {
		if err.Error() == "not found" {
			return nil, abstract.ResourceNotFoundError("bucket", name)
		}
		return nil, scerr.NewError(err, nil, "failed to read bucket information")
	}
	b.Name = pb.GetName()
	b.ID = pb.GetID()

	return b, nil
}

// Create a bucket
func (b *bucket) Create(task concurrency.Task, name string) (err error) {
	if b == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if name == "" {
		return scerr.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(task, true, "('"+name+"')").WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	bucket, err := b.svc.GetBucket(name)
	if err != nil {
		if err.Error() != "not found" {
			return err
		}
	}
	if bucket != nil {
		return abstract.ResourceDuplicateError("bucket", name)
	}
	_, err = b.svc.CreateBucket(name)
	if err != nil {
		return err
	}
	return nil
}

// Delete a bucket
func (b *bucket) Delete(ctx context.Context, name string) (err error) {
	tracer := concurrency.NewTracer(nil, true, "('"+name+"')").WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	return b.svc.DeleteBucket(name)
}

// Mount a bucket on an host on the given mount point
func (b *bucket) Mount(ctx context.Context, bucketName, hostName, path string) (err error) {
	tracer := concurrency.NewTracer(nil, true, "('%s', '%s', '%s')", bucketName, hostName, path).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	// Check bucket existence
	_, err = b.svc.GetBucket(bucketName)
	if err != nil {
		return err
	}

	// Get Host ID
	host, err := operations.LoadHost(task, b.svc, hostName)
	if err != nil {
		return fmt.Errorf("no host found with name or id '%s'", hostName)
	}

	// Create mount point
	mountPoint := path
	if path == resources.DefaultBucketMountPoint {
		mountPoint = resources.DefaultBucketMountPoint + bucketName
	}

	authOpts, _ := b.svc.GetAuthenticationOptions()
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

	objStorageProtocol := b.svc.GetObjectStorageProtocol()
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

	rerr := exec(ctx, "mount_object_storage.sh", data, host.SafeGetID(), b.svc)
	return rerr
}

// Unmount a bucket
func (b *bucket) Unmount(ctx context.Context, bucketName, hostName string) (err error) {
	tracer := concurrency.NewTracer(nil, true, "('%s', '%s')", bucketName, hostName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	// Check bucket existence
	_, err = b.svc.Inspect(ctx, bucketName)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); ok {
			return err
		}
		return err
	}

	// Get Host ID
	host, err := operations.LoadHost(task, b.svc, hostName)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); ok {
			return err
		}
		return err
	}

	data := struct {
		Bucket string
	}{
		Bucket: bucketName,
	}

	rerr := exec(ctx, "umount_object_storage.sh", data, host.SafeGetID(), b.svc)
	return rerr
}
