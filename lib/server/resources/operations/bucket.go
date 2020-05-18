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

package operations

//go:generate rice embed-go

import (
	"bytes"
	"html/template"
	"regexp"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
	rice "github.com/GeertJohan/go.rice"
)

// bucket describes a bucket and satisfies interface resources.Bucket
type bucket struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Host       string `json:"host,omitempty"`
	MountPoint string `json:"mountPoint,omitempty"`
	// NbItems    int    `json:"nbitems,omitempty"`

	svc iaas.Service
}

// NewBucket intanciantes bucket struct
func NewBucket(svc iaas.Service) (resources.Bucket, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}
	b := &bucket{
		svc: svc,
	}
	return b, nil
}

// LoadBucket instanciantes a bucket struct and fill it with Provider metadata of Object Storage Bucket
func LoadBucket(svc iaas.Service, name string) (_ resources.Bucket, xerr fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(nil, true, "('"+name+"')").WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &xerr)

	anon, xerr := NewBucket(svc)
	if xerr != nil {
		return nil, xerr
	}
	b := anon.(*bucket)

	if _, xerr = svc.InspectBucket(name); xerr != nil {
		if xerr.Error() == "not found" {
			return nil, abstract.ResourceNotFoundError("bucket", name)
		}
		return nil, fail.NewError(xerr, nil, "failed to read bucket information")
	}
	b.Name = name
	b.ID = name

	return b, nil
}

// IsNull tells if the instance corresponds to null value
func (b *bucket) IsNull() bool {
	return b == nil || b.svc == nil
}

// SafeGetID returns the ID of the bucket
func (b *bucket) SafeGetID() string {
	if b.IsNull() {
		return ""
	}
	return b.ID
}

// SafeGetName returns the name of the bucket
func (b *bucket) SafeGetName() string {
	if b.IsNull() {
		return ""
	}
	return b.Name
}

func (b *bucket) SafeGetHost() string {
	if b.IsNull() {
		return ""
	}
	return b.Host
}

func (b *bucket) SafeGetMountPoint() string {
	if b.IsNull() {
		return ""
	}
	return b.MountPoint
}

// Create a bucket
func (b *bucket) Create(task concurrency.Task, name string) (xerr fail.Error) {
	if b == nil {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(task, true, "('"+name+"')").WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &xerr)

	bucket, xerr := b.svc.InspectBucket(name)
	if xerr != nil {
		if _, ok := xerr.(fail.ErrNotFound); !ok {
			return xerr
		}
	}
	if bucket != nil {
		return abstract.ResourceDuplicateError("bucket", name)
	}
	if _, xerr = b.svc.CreateBucket(name); xerr != nil {
		return xerr
	}
	b.Name = name
	b.ID = name

	return nil
}

// Delete a bucket
func (b *bucket) Delete(task concurrency.Task) (xerr fail.Error) {
	tracer := concurrency.NewTracer(task, true, "").WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &xerr)

	return b.svc.DeleteBucket(b.SafeGetName())
}

// Mount a bucket on an host on the given mount point
func (b *bucket) Mount(task concurrency.Task, hostName, path string) (xerr fail.Error) {
	tracer := concurrency.NewTracer(task, true, "('%s', '%s')", hostName, path).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &xerr)

	// Get Host data
	rh, xerr := LoadHost(task, b.svc, hostName)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to mount bucket '%s' on rh '%s'", b.SafeGetName(), hostName)
	}

	// Create mount point
	mountPoint := path
	if path == abstract.DefaultBucketMountPoint {
		mountPoint = abstract.DefaultBucketMountPoint + b.SafeGetName()
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

	objStorageProtocol := b.svc.SafeGetObjectStorageProtocol()
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
		Bucket:     b.SafeGetName(),
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
	tracer := concurrency.NewTracer(task, true, "('%s')", hostName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &xerr)

	defer func() {
		if xerr != nil {
			xerr = fail.Wrap(xerr, "failed to unmount bucket '%s' from rh '%s'", b.SafeGetName(), hostName)
		}
	}()

	// Check bucket existence
	if _, xerr = b.svc.InspectBucket(b.SafeGetName()); xerr != nil {
		return xerr
	}

	// Get Host ID
	rh, xerr := LoadHost(task, b.svc, hostName)
	if xerr != nil {
		return xerr
	}

	data := struct {
		Bucket string
	}{
		Bucket: b.SafeGetName(),
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

// Return the script (embeded in a rice-box) with placeholders replaced by the values given in data
func getBoxContent(script string, data interface{}) (tplcmd string, xerr fail.Error) {
	defer fail.OnExitLogError(concurrency.NewTracer(nil, true, "").TraceMessage(""), &xerr)

	box, err := rice.FindBox("../operations/scripts")
	if err != nil {
		return "", fail.ToError(err)
	}
	scriptContent, err := box.String(script)
	if err != nil {
		return "", fail.ToError(err)
	}
	tpl, err := template.New("TemplateName").Parse(scriptContent)
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
