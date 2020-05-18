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
	"fmt"
	"io"
	"strings"

	"github.com/sirupsen/logrus"
	"gomodules.xyz/stow"

	// necessary for connect
	// _ "gomodules.xyz/stow/azure"
	_ "gomodules.xyz/stow/google"
	_ "gomodules.xyz/stow/s3"
	_ "gomodules.xyz/stow/swift"

	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// location ...
type location struct {
	stowLocation stow.Location
	config       Config

	NbItem           int
	IdentityEndpoint string
	TenantName       string
	Password         string
	Username         string
	Region           string
}

// NewLocation creates an Object Storage Location based on config
func NewLocation(conf Config) (Location, fail.Error) {
	location := &location{
		config: conf,
	}
	err := location.connect()
	if err != nil {
		return nil, err
	}
	return location, nil
}

// func (l *location) getStowLocation() stow.Location {
// 	return l.stowLocation
// }

// Connect connects to an Object Storage Location
func (l *location) connect() fail.Error {
	// FIXME GCP Remove specific driver code, Google requires a custom cfg here..., this will require a refactoring based on stow.ConfigMap
	var config stow.ConfigMap

	if l.config.Type == "google" {
		config = stow.ConfigMap{
			"json":       l.config.Credentials,
			"project_id": l.config.ProjectID,
		}
	} else {
		config = stow.ConfigMap{
			"access_key_id":   l.config.User,
			"secret_key":      l.config.SecretKey,
			"username":        l.config.User,
			"key":             l.config.SecretKey,
			"endpoint":        l.config.Endpoint,
			"tenant_name":     l.config.Tenant,
			"tenant_auth_url": l.config.AuthURL,
			"region":          l.config.Region,
			"domain":          l.config.TenantDomain,
			"kind":            l.config.Type,
		}
	}
	kind := l.config.Type

	// Check config location
	err := stow.Validate(kind, config)
	if err != nil {
		logrus.Debugf("invalid config: %v", err)
		return fail.ToError(err)
	}
	l.stowLocation, err = stow.Dial(kind, config)
	if err != nil {
		logrus.Debugf("failed dialing location: %v", err)
	}
	return fail.ToError(err)
}

// SafeGetObjectStorageProtocol returns the type of ObjectStorage
func (l location) SafeGetObjectStorageProtocol() string {
	return l.config.Type
}

// ListBuckets ...
func (l *location) ListBuckets(prefix string) ([]string, fail.Error) {
	if l == nil {
		return nil, fail.InvalidInstanceError()
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("objectstorage.location"), "('%s')", prefix).Entering().OnExitTrace()

	var list []string
	err := stow.WalkContainers(l.stowLocation, stow.NoPrefix, 100,
		func(c stow.Container, err error) error {
			if err != nil {
				return err
			}
			if strings.Index(c.Name(), prefix) == 0 {
				list = append(list, c.Name())
			}
			return nil
		},
	)
	if err != nil {
		return nil, fail.ToError(err)
	}
	return list, nil
}

// FindBucket returns true if a bucket with the name exists in location
func (l *location) FindBucket(bucketName string) (bool, fail.Error) {
	if l == nil {
		return false, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return false, fail.InvalidParameterError("bucketName", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("objectstorage.location"), "(%s)", bucketName).Entering().OnExitTrace()

	found := false
	err := stow.WalkContainers(l.stowLocation, stow.NoPrefix, 100,
		func(c stow.Container, err error) error {
			if err != nil {
				logrus.Debugf("%v", err)
				return err
			}
			if c.Name() == bucketName {
				found = true
				return fmt.Errorf("found")
			}
			return nil
		},
	)
	if found {
		return true, nil
	}
	return false, fail.ToError(err)
}

// GetBucket ...
func (l *location) InspectBucket(bucketName string) (Bucket, fail.Error) {
	if l == nil {
		return nil, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return nil, fail.InvalidParameterError("bucketName", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("objectstorage.location"), "(%s)", bucketName).Entering().OnExitTrace()

	b, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return nil, err
	}
	var cerr error
	b.container, cerr = l.stowLocation.Container(bucketName)
	if cerr != nil {
		// Note: No errors.Wrap here; error needs to be transmitted as-is
		return nil, fail.ToError(err)
	}
	return b, nil
}

// CreateBucket ...
func (l *location) CreateBucket(bucketName string) (Bucket, fail.Error) {
	if l == nil {
		return nil, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return nil, fail.InvalidParameterError("bucketName", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("objectstorage.location"), "('%s')", bucketName).Entering().OnExitTrace()

	c, err := l.stowLocation.CreateContainer(bucketName)
	if err != nil {
		return nil, fail.Wrap(err, fmt.Sprintf("failure creating bucket '%s'", bucketName))
	}
	return &bucket{
		location:  l.stowLocation,
		container: c,
		Name:      c.Name(),
	}, nil
}

// DeleteBucket removes a bucket from Object Storage
func (l *location) DeleteBucket(bucketName string) fail.Error {
	if l == nil {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterError("bucketName", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("objectstorage.location"), "('%s')", bucketName).Entering().OnExitTrace()

	err := l.stowLocation.RemoveContainer(bucketName)
	if err != nil {
		return fail.ToError(err)
	}
	return nil
}

// InspectObject ...
func (l *location) InspectObject(bucketName string, objectName string) (Object, fail.Error) {
	if l == nil {
		return nil, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return nil, fail.InvalidParameterError("bucketName", "cannot be empty string")
	}
	if objectName == "" {
		return nil, fail.InvalidParameterError("objectName", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("objectstorage.location"), "('%s', '%s')", bucketName, objectName).Entering().OnExitTrace()

	bucket, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return nil, err
	}
	return newObject(bucket, objectName)
}

// DeleteObject ...
func (l *location) DeleteObject(bucketName, objectName string) fail.Error {
	if l == nil {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterError("bucketName", "cannot be empty string")
	}
	if objectName == "" {
		return fail.InvalidParameterError("objectName", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("objectstorage.location"), "('%s', '%s')", bucketName, objectName).Entering().OnExitTrace()

	bucket, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return err
	}
	return bucket.DeleteObject(objectName)
}

// ListObjects lists the objects in a Bucket
func (l *location) ListObjects(bucketName string, path, prefix string) ([]string, fail.Error) {
	if l == nil {
		return nil, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return nil, fail.InvalidParameterError("bucketName", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("objectstorage.location"), "('%s', '%s', '%s')", bucketName, path, prefix).Entering().OnExitTrace()

	b, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return nil, err
	}
	return b.List(path, prefix)
}

// Browse walks through the objects in a Bucket and apply callback to each object
func (l *location) BrowseBucket(bucketName string, path, prefix string, callback func(o Object) fail.Error) fail.Error {
	if l == nil {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterError("bucketName", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("objectstorage.location"), "('%s', '%s', '%s')", bucketName, path, prefix).Entering().OnExitTrace()

	b, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return err
	}
	return b.Browse(path, prefix, callback)
}

// ClearBucket ...
func (l *location) ClearBucket(bucketName string, path, prefix string) fail.Error {
	if l == nil {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterError("bucketName", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("objectstorage.location"), "('%s', '%s', '%s')", bucketName, path, prefix).Entering().OnExitTrace()

	b, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return err
	}
	return b.Clear(path, prefix)
}

// ReadObject reads the content of an object and put it in an io.Writer
func (l *location) ReadObject(bucketName, objectName string, writer io.Writer, from, to int64) fail.Error {
	if l == nil {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterError("bucketName", "cannot be empty string")
	}
	if objectName == "" {
		return fail.InvalidParameterError("objectName", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("objectstorage.location"), "('%s', '%s')", bucketName, objectName).Entering().OnExitTrace()

	b, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return err
	}
	o, err := newObject(b, objectName)
	if err != nil {
		return err
	}
	err = o.Read(writer, from, to)
	if err != nil {
		return err
	}
	return nil
}

// WriteObject writes the content of reader in the Object
func (l *location) WriteObject(
	bucketName string, objectName string,
	source io.Reader, size int64,
	metadata ObjectMetadata,
) (Object, fail.Error) {

	if l == nil {
		return nil, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return nil, fail.InvalidParameterError("bucketName", "cannot be empty string")
	}
	if objectName == "" {
		return nil, fail.InvalidParameterError("objectName", "cannot be empty string")
	}
	if source == nil {
		return nil, fail.InvalidParameterError("source", "cannot be nil")
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("objectstorage.location"), "('%s', '%s', %d)", bucketName, objectName, size).Entering().OnExitTrace()

	b, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return nil, err
	}
	return b.WriteObject(objectName, source, size, metadata)
}

// WriteMultiPartObject writes data from 'source' to an object in Object Storage, splitting data in parts of 'chunkSize' bytes
// Note: nothing to do with multi-chunk abilities of various object storage technologies
func (l *location) WriteMultiPartObject(
	bucketName string, objectName string,
	source io.Reader, sourceSize int64,
	chunkSize int,
	metadata ObjectMetadata,
) (Object, fail.Error) {

	if l == nil {
		return nil, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return nil, fail.InvalidParameterError("bucketName", "cannot be empty string")
	}
	if objectName == "" {
		return nil, fail.InvalidParameterError("objectName", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, debug.ShouldTrace("objectstorage.location"), "('%s', '%s', %d, %d)", bucketName, objectName, sourceSize, chunkSize).Entering().OnExitTrace()

	bucket, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return nil, err
	}
	return bucket.WriteMultiPartObject(objectName, source, sourceSize, chunkSize, metadata)
}
