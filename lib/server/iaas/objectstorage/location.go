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

package objectstorage

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"

	"github.com/ncw/swift"

	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"

	log "github.com/sirupsen/logrus"

	"github.com/graymeta/stow"
	// necessary for connect
	// _ "github.com/graymeta/stow/azure"
	_ "github.com/graymeta/stow/google"
	_ "github.com/graymeta/stow/s3"
	_ "github.com/graymeta/stow/swift"
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

func transformErrors(in error) error {
	if in == nil {
		return nil
	}

	if in == stow.ErrNotFound {
		return fail.NotFoundError(in.Error())
	}

	if ne, ok := in.(net.Error); ok {
		if ne.Temporary() || ne.Timeout() {
			return fail.TimeoutError("timeout accessing object storage", 0, ne)
		}

		return in
	}

	if se, ok := in.(*swift.Error); ok {
		if se.StatusCode == 404 {
			return fail.NotFoundError(se.Error())
		}

		if se.StatusCode == 408 {
			return fail.TimeoutError("timeout accessing object storage", 0, se)
		}

		if errors.Is(se, swift.TimeoutError) {
			return fail.TimeoutError("timeout accessing object storage", 0, se)
		}

		return in
	}

	if ue, ok := in.(*url.Error); ok {
		if ue.Timeout() || ue.Temporary() {
			return fail.TimeoutError("timeout accessing object storage", 0, ue)
		}

		return in
	}

	if strings.Contains(in.Error(), "imeout") {
		return fail.TimeoutError("timeout accessing object storage", 0, in)
	}

	return in
}

// NewLocation creates an Object Storage Location based on config
func NewLocation(conf Config) (Location, error) {
	location := &location{
		config: conf,
	}
	err := location.connect()
	if err != nil {
		return nil, transformErrors(err)
	}
	return location, nil
}

func (l *location) getStowLocation() stow.Location {
	return l.stowLocation
}

// Connect connects to an Object Storage Location
func (l *location) connect() error {
	// FIXME: GCP Remove specific driver code, Google requires a custom cfg here..., this will require a refactoring based on stow.ConfigMap
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
		return transformErrors(err)
	}
	l.stowLocation, err = stow.Dial(kind, config)
	if err != nil {
		return transformErrors(err)
	}
	return transformErrors(err)
}

// GetType returns the type of ObjectStorage
func (l location) GetType() string {
	return l.config.Type
}

// ListBuckets ...
func (l *location) ListBuckets(prefix string) ([]string, error) {
	if l == nil {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, fmt.Sprintf("('%s')", prefix), false /*Trace.Location*/).GoingIn().OnExitTrace()()

	var list []string
	err := stow.WalkContainers(
		l.stowLocation, stow.NoPrefix, 100,
		func(c stow.Container, err error) error {
			if err != nil {
				return transformErrors(err)
			}
			if strings.Index(c.Name(), prefix) == 0 {
				list = append(list, c.Name())
			}
			return nil
		},
	)
	if err != nil {
		return nil, transformErrors(err)
	}
	return list, nil
}

// findBucket returns true if a bucket with the name exists in location
func (l *location) FindBucket(bucketName string) (bool, error) {
	if l == nil {
		return false, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return false, fail.InvalidParameterError("bucketName", "cannot be empty string")
	}

	defer debug.NewTracer(nil, fmt.Sprintf("(%s)", bucketName), false /*Trace.Location*/).GoingIn().OnExitTrace()()

	found := false
	err := stow.WalkContainers(
		l.stowLocation, stow.NoPrefix, 100,
		func(c stow.Container, err error) error {
			if err != nil {
				log.Debugf("%v", err)
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
	return false, transformErrors(err)
}

// GetBucket ...
func (l *location) GetBucket(bucketName string) (Bucket, error) {
	if l == nil {
		return nil, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return nil, fail.InvalidParameterError("bucketName", "cannot be empty string")
	}

	defer debug.NewTracer(nil, fmt.Sprintf("(%s)", bucketName), false /*Trace.Location*/).GoingIn().OnExitTrace()()

	b, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return nil, transformErrors(err)
	}
	b.container, err = l.stowLocation.Container(bucketName)
	if err != nil {
		// Note: No errors.Wrap here; error needs to be transmitted as-is
		return nil, transformErrors(err)
	}
	return b, nil
}

// CreateBucket ...
func (l *location) CreateBucket(bucketName string) (Bucket, error) {
	if l == nil {
		return nil, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return nil, fail.InvalidParameterError("bucketName", "cannot be empty string")
	}

	defer debug.NewTracer(nil, fmt.Sprintf("('%s')", bucketName), false /*Trace.Location*/).GoingIn().OnExitTrace()()

	c, err := l.stowLocation.CreateContainer(bucketName)
	if err != nil {
		return nil, transformErrors(err)
	}
	return &bucket{
		location:  l.stowLocation,
		container: c,
		Name:      c.Name(),
	}, nil
}

// DeleteBucket removes a bucket from Object Storage
func (l *location) DeleteBucket(bucketName string) error {
	if l == nil {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterError("bucketName", "cannot be empty string")
	}

	defer debug.NewTracer(nil, fmt.Sprintf("('%s')", bucketName), false /*Trace.Location*/).GoingIn().OnExitTrace()()

	err := l.stowLocation.RemoveContainer(bucketName)
	return transformErrors(err)
}

// GetObject ...
func (l *location) GetObject(bucketName string, objectName string) (Object, error) {
	if l == nil {
		return nil, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return nil, fail.InvalidParameterError("bucketName", "cannot be empty string")
	}
	if objectName == "" {
		return nil, fail.InvalidParameterError("objectName", "cannot be empty string")
	}

	defer debug.NewTracer(
		nil, fmt.Sprintf("('%s', '%s')", bucketName, objectName), false, /*Trace.Location*/
	).GoingIn().OnExitTrace()()

	bucket, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return nil, transformErrors(err)
	}

	bucket.container, err = l.stowLocation.Container(bucketName)
	if err != nil {
		return nil, transformErrors(err)
	}

	ob, err := newObject(bucket, objectName)
	return ob, transformErrors(err)
}

// DeleteObject ...
func (l *location) DeleteObject(bucketName, objectName string) error {
	if l == nil {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterError("bucketName", "cannot be empty string")
	}
	if objectName == "" {
		return fail.InvalidParameterError("objectName", "cannot be empty string")
	}

	defer debug.NewTracer(
		nil, fmt.Sprintf("('%s', '%s')", bucketName, objectName), false, /*Trace.Location*/
	).GoingIn().OnExitTrace()()

	bucket, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return transformErrors(err)
	}

	bucket.container, err = l.stowLocation.Container(bucketName)
	if err != nil {
		return transformErrors(err)
	}

	err = bucket.DeleteObject(objectName)
	return transformErrors(err)
}

// ListObjects lists the objects in a Bucket
func (l *location) ListObjects(bucketName string, path, prefix string) ([]string, error) {
	if l == nil {
		return nil, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return nil, fail.InvalidParameterError("bucketName", "cannot be empty string")
	}

	defer debug.NewTracer(
		nil, fmt.Sprintf("('%s', '%s', '%s')", bucketName, path, prefix), false, /*Trace.Location*/
	).GoingIn().OnExitTrace()()

	b, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return nil, transformErrors(err)
	}

	b.container, err = l.stowLocation.Container(bucketName)
	if err != nil {
		return nil, transformErrors(err)
	}

	ob, err := b.List(path, prefix)
	return ob, transformErrors(err)
}

// Browse walks through the objects in a Bucket and apply callback to each object
func (l *location) BrowseBucket(bucketName string, path, prefix string, callback func(o Object) error) error {
	if l == nil {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterError("bucketName", "cannot be empty string")
	}

	defer debug.NewTracer(
		nil, fmt.Sprintf("('%s', '%s', '%s')", bucketName, path, prefix), false, /*Trace.Location*/
	).GoingIn().OnExitTrace()()

	b, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return transformErrors(err)
	}

	b.container, err = l.stowLocation.Container(bucketName)
	if err != nil {
		return transformErrors(err)
	}

	err = b.Browse(path, prefix, callback)
	return transformErrors(err)
}

// ClearBucket ...
func (l *location) ClearBucket(bucketName string, path, prefix string) error {
	if l == nil {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterError("bucketName", "cannot be empty string")
	}

	defer debug.NewTracer(
		nil, fmt.Sprintf("('%s', '%s', '%s')", bucketName, path, prefix), false, /*Trace.Location*/
	).GoingIn().OnExitTrace()()

	b, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return transformErrors(err)
	}

	b.container, err = l.stowLocation.Container(bucketName)
	if err != nil {
		return transformErrors(err)
	}

	err = b.Clear(path, prefix)
	return transformErrors(err)
}

// ReadObject reads the content of an object and put it in an io.Writer
func (l *location) ReadObject(bucketName, objectName string, writer io.Writer, from, to int64) error {
	if l == nil {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterError("bucketName", "cannot be empty string")
	}
	if objectName == "" {
		return fail.InvalidParameterError("objectName", "cannot be empty string")
	}

	defer debug.NewTracer(
		nil, fmt.Sprintf("('%s', '%s')", bucketName, objectName), false, /*Trace.Location*/
	).GoingIn().OnExitTrace()()

	b, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return transformErrors(err)
	}
	b.container, err = l.stowLocation.Container(bucketName)
	if err != nil {
		return transformErrors(err)
	}
	o, err := newObject(b, objectName)
	if err != nil {
		return transformErrors(err)
	}
	err = o.Read(writer, from, to)
	return transformErrors(err)
}

// WriteObject writes the content of reader in the Object
func (l *location) WriteObject(
	bucketName string, objectName string,
	source io.Reader, size int64,
	metadata ObjectMetadata,
) (Object, error) {

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

	defer debug.NewTracer(
		nil, fmt.Sprintf("('%s', '%s', %d)", bucketName, objectName, size), false, /*Trace.Location*/
	).GoingIn().OnExitTrace()()

	b, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return nil, transformErrors(err)
	}
	b.container, err = l.stowLocation.Container(bucketName)
	if err != nil {
		return nil, transformErrors(err)
	}
	ob, err := b.WriteObject(objectName, source, size, metadata)
	return ob, transformErrors(err)
}

// WriteMultiPartObject writes data from 'source' to an object in Object Storage, splitting data in parts of 'chunkSize' bytes
// Note: nothing to do with multi-chunk abilities of various object storage technologies
func (l *location) WriteMultiPartObject(
	bucketName string, objectName string,
	source io.Reader, sourceSize int64,
	chunkSize int,
	metadata ObjectMetadata,
) (Object, error) {

	if l == nil {
		return nil, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return nil, fail.InvalidParameterError("bucketName", "cannot be empty string")
	}
	if objectName == "" {
		return nil, fail.InvalidParameterError("objectName", "cannot be empty string")
	}

	defer debug.NewTracer(
		nil, fmt.Sprintf("('%s', '%s', %d, %d)", bucketName, objectName, sourceSize, chunkSize),
		false, /*Trace.Location*/
	).GoingIn().OnExitTrace()()

	bucket, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return nil, transformErrors(err)
	}
	bucket.container, err = l.stowLocation.Container(bucketName)
	if err != nil {
		return nil, transformErrors(err)
	}
	ob, err := bucket.WriteMultiPartObject(objectName, source, sourceSize, chunkSize, metadata)
	return ob, transformErrors(err)
}
