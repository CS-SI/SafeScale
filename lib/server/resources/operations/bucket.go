/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

package operations

//go:generate rice embed-go

import (
	"bytes"
	"reflect"
	"regexp"

	rice "github.com/GeertJohan/go.rice"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/template"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	// bucketsFolderName is the technical name of the object storage folder used to store buckets info
	bucketsFolderName = "buckets"
)

// bucket describes a bucket and satisfies interface resources.ObjectStorageBucket
type bucket struct {
	*core

	// GetID         string `json:"id,omitempty"`
	// GetName       string `json:"name,omitempty"`
	// IPAddress       string `json:"host,omitempty"`
	// MountPoint string `json:"mountPoint,omitempty"`
	// // NbItems    int    `json:"nbitems,omitempty"`

	svc iaas.Service
	// location objectstorage.Location
	// container objectstorage.Bucket
}

// NewBucket intanciates bucket struct
func NewBucket(svc iaas.Service) (resources.Bucket, fail.Error) {
	if svc.IsNull() {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	coreInstance, xerr := newCore(svc, "bucket", bucketsFolderName, &abstract.ObjectStorageBucket{})
	if xerr != nil {
		return nil, xerr
	}

	b := &bucket{
		core: coreInstance,
		svc:  svc,
	}
	return b, nil
}

// LoadBucket instanciates a bucket struct and fill it with Provider metadata of Object Storage ObjectStorageBucket
func LoadBucket(task concurrency.Task, svc iaas.Service, name string) (_ resources.Bucket, xerr fail.Error) {
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}
	if svc.IsNull() {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(task, true, "('"+name+"')").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	anon, xerr := NewBucket(svc)
	if xerr != nil {
		return nil, xerr
	}
	b := anon.(*bucket)

	ab, xerr := svc.InspectBucket(name)
	if xerr != nil {
		if xerr.Error() == "not found" {
			return nil, abstract.ResourceNotFoundError("bucket", name)
		}
		return nil, fail.NewError(xerr, nil, "failed to read bucket information")
	}
	xerr = b.Carry(task, &ab)
	if xerr != nil {
		return nil, xerr
	}
	return b, nil
}

// IsNull tells if the instance corresponds to null value
func (b *bucket) IsNull() bool {
	return b == nil || b.core.IsNull()
}

// GetHost ...
func (b *bucket) GetHost(task concurrency.Task) (string, fail.Error) {
	if b.IsNull() {
		return "", fail.InvalidInstanceError()
	}
	var res string
	xerr := b.core.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		ab, ok := clonable.(*abstract.ObjectStorageBucket)
		if !ok {
			return fail.InconsistentError("'*abstract.ObjectStorageBucket' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		res = ab.Host
		return nil
	})
	if xerr != nil {
		return res, xerr
	}
	return res, nil
}

// Host ...
func (b *bucket) Host(task concurrency.Task) string {
	res, _ := b.GetHost(task)
	return res
}

// GetMountPoint ...
func (b *bucket) GetMountPoint(task concurrency.Task) (string, fail.Error) {
	if b.IsNull() {
		return "", fail.InvalidInstanceError()
	}
	var res string
	xerr := b.core.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		ab, ok := clonable.(*abstract.ObjectStorageBucket)
		if !ok {
			return fail.InconsistentError("'*abstract.ObjectStorageBucket' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		res = ab.MountPoint
		return nil
	})
	if xerr != nil {
		logrus.Errorf(xerr.Error())
	}
	return res, nil
}

// MountPoint ...
func (b *bucket) MountPoint(task concurrency.Task) string {
	res, _ := b.GetMountPoint(task)
	return res
}

// Create a bucket
func (b *bucket) Create(task concurrency.Task, name string) (xerr fail.Error) {
	if b == nil {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(task, true, "('"+name+"')").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	ab, xerr := b.svc.InspectBucket(name)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok {
			return xerr
		}
	}
	if !ab.IsNull() {
		return abstract.ResourceDuplicateError("bucket", name)
	}
	if ab, xerr = b.svc.CreateBucket(name); xerr != nil {
		return xerr
	}

	return b.core.Carry(task, &ab)
}

// Delete a bucket
func (b *bucket) Delete(task concurrency.Task) (xerr fail.Error) {
	tracer := debug.NewTracer(task, true, "").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	return b.svc.DeleteBucket(b.GetName())
}

// Mount a bucket on an host on the given mount point
func (b *bucket) Mount(task concurrency.Task, hostName, path string) (xerr fail.Error) {
	tracer := debug.NewTracer(task, true, "('%s', '%s')", hostName, path).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	// Get IPAddress data
	rh, xerr := LoadHost(task, b.svc, hostName)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to mount bucket '%s' on rh '%s'", b.GetName(), hostName)
	}

	// Create mount point
	mountPoint := path
	if path == abstract.DefaultBucketMountPoint {
		mountPoint = abstract.DefaultBucketMountPoint + b.GetName()
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

	objStorageProtocol := b.svc.ObjectStorageProtocol()
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
		Bucket:     b.GetName(),
		Tenant:     tenant,
		Login:      login,
		Password:   password,
		AuthURL:    authurl,
		Region:     region,
		MountPoint: mountPoint,
		Protocol:   objStorageProtocol,
	}

	err := b.exec(task, rh, "mount_object_storage.sh", data)
	return fail.ToError(err)
}

// Unmount a bucket
func (b *bucket) Unmount(task concurrency.Task, hostName string) (xerr fail.Error) {
	tracer := debug.NewTracer(task, true, "('%s')", hostName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	defer func() {
		if xerr != nil {
			xerr = fail.Wrap(xerr, "failed to unmount bucket '%s' from rh '%s'", b.GetName(), hostName)
		}
	}()

	// Check bucket existence
	if _, xerr = b.svc.InspectBucket(b.GetName()); xerr != nil {
		return xerr
	}

	// Get IPAddress ID
	rh, xerr := LoadHost(task, b.svc, hostName)
	if xerr != nil {
		return xerr
	}

	data := struct {
		Bucket string
	}{
		Bucket: b.GetName(),
	}

	err := b.exec(task, rh, "umount_object_storage.sh", data)
	return fail.ToError(err)
}

// Execute the given script (embedded in a rice-box) with the given data on the host identified by hostid
func (b *bucket) exec(task concurrency.Task, host resources.Host, script string, data interface{}) fail.Error {
	scriptCmd, xerr := getBoxContent(script, data)
	if xerr != nil {
		return xerr
	}

	_, _, _, xerr = host.Run(task, `sudo `+scriptCmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	return xerr
}

// Return the script (embedded in a rice-box) with placeholders replaced by the values given in data
func getBoxContent(script string, data interface{}) (tplcmd string, xerr fail.Error) {
	defer fail.OnExitLogError(&xerr, debug.NewTracer(nil, true, "").TraceMessage(""))

	box, err := rice.FindBox("../operations/scripts")
	if err != nil {
		return "", fail.ToError(err)
	}
	scriptContent, err := box.String(script)
	if err != nil {
		return "", fail.ToError(err)
	}
	tpl, err := template.Parse("TemplateName", scriptContent)
	if err != nil {
		return "", fail.ToError(err)
	}

	var buffer bytes.Buffer
	if err = tpl.Execute(&buffer, data); err != nil {
		return "", fail.ToError(err)
	}

	tplcmd = buffer.String()
	// fmt.Println(tplcmd)
	return tplcmd, nil
}
