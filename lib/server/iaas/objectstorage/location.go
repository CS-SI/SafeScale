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

package objectstorage

import (
	"fmt"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"io"
	"strings"

	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
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

// NewLocation creates an Object Storage Location based on config
func NewLocation(conf Config) (Location, error) {
	location := &location{
		config: conf,
	}
	err := location.connect()
	if err != nil {
		return nil, err
	}
	return location, nil
}

func (l *location) getStowLocation() stow.Location {
	return l.stowLocation
}

// Connect connects to an Object Storage Location
func (l *location) connect() error {
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
		log.Debugf("invalid config: %v", err)
		return err
	}
	l.stowLocation, err = stow.Dial(kind, config)
	if err != nil {
		log.Debugf("failed dialing location: %v", err)
		return err
	}
	return err
}

// GetType returns the type of ObjectStorage
func (l location) GetType() string {
	return l.config.Type
}

// ListBuckets ...
func (l *location) ListBuckets(prefix string) ([]string, error) {
	if l == nil {
		return nil, scerr.InvalidInstanceError()
	}

	defer concurrency.NewTracer(nil, fmt.Sprintf("('%s')", prefix), false /*Trace.Location*/).GoingIn().OnExitTrace()()

	list := []string{}
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
		return nil, err
	}
	return list, nil
}

// findBucket returns true if a bucket with the name exists in location
func (l *location) FindBucket(bucketName string) (bool, error) {
	if l == nil {
		return false, scerr.InvalidInstanceError()
	}
	if bucketName == "" {
		return false, scerr.InvalidParameterError("bucketName", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, fmt.Sprintf("(%s)", bucketName), false /*Trace.Location*/).GoingIn().OnExitTrace()()

	found := false
	err := stow.WalkContainers(l.stowLocation, stow.NoPrefix, 100,
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
	return false, err
}

// GetBucket ...
func (l *location) GetBucket(bucketName string) (Bucket, error) {
	if l == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if bucketName == "" {
		return nil, scerr.InvalidParameterError("bucketName", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, fmt.Sprintf("(%s)", bucketName), false /*Trace.Location*/).GoingIn().OnExitTrace()()

	b, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return nil, err
	}
	b.container, err = l.stowLocation.Container(bucketName)
	if err != nil {
		//Note: No errors.Wrap here; error needs to be transmitted as-is
		return nil, err
	}
	return b, nil
}

// CreateBucket ...
func (l *location) CreateBucket(bucketName string) (Bucket, error) {
	if l == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if bucketName == "" {
		return nil, scerr.InvalidParameterError("bucketName", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, fmt.Sprintf("('%s')", bucketName), false /*Trace.Location*/).GoingIn().OnExitTrace()()

	c, err := l.stowLocation.CreateContainer(bucketName)
	if err != nil {
		return nil, err
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
		return scerr.InvalidInstanceError()
	}
	if bucketName == "" {
		return scerr.InvalidParameterError("bucketName", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, fmt.Sprintf("('%s')", bucketName), false /*Trace.Location*/).GoingIn().OnExitTrace()()

	err := l.stowLocation.RemoveContainer(bucketName)
	if err != nil {
		return err
	}
	return nil
}

// GetObject ...
func (l *location) GetObject(bucketName string, objectName string) (Object, error) {
	if l == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if bucketName == "" {
		return nil, scerr.InvalidParameterError("bucketName", "cannot be empty string")
	}
	if objectName == "" {
		return nil, scerr.InvalidParameterError("objectName", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s')", bucketName, objectName), false /*Trace.Location*/).GoingIn().OnExitTrace()()

	bucket, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return nil, err
	}
	return newObject(bucket, objectName)
}

// DeleteObject ...
func (l *location) DeleteObject(bucketName, objectName string) error {
	if l == nil {
		return scerr.InvalidInstanceError()
	}
	if bucketName == "" {
		return scerr.InvalidParameterError("bucketName", "cannot be empty string")
	}
	if objectName == "" {
		return scerr.InvalidParameterError("objectName", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s')", bucketName, objectName), false /*Trace.Location*/).GoingIn().OnExitTrace()()

	bucket, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return err
	}
	return bucket.DeleteObject(objectName)
}

// ListObjects lists the objects in a Bucket
func (l *location) ListObjects(bucketName string, path, prefix string) ([]string, error) {
	if l == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if bucketName == "" {
		return nil, scerr.InvalidParameterError("bucketName", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s', '%s')", bucketName, path, prefix), false /*Trace.Location*/).GoingIn().OnExitTrace()()

	b, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return nil, err
	}
	return b.List(path, prefix)
}

// Browse walks through the objects in a Bucket and apply callback to each object
func (l *location) BrowseBucket(bucketName string, path, prefix string, callback func(o Object) error) error {
	if l == nil {
		return scerr.InvalidInstanceError()
	}
	if bucketName == "" {
		return scerr.InvalidParameterError("bucketName", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s', '%s')", bucketName, path, prefix), false /*Trace.Location*/).GoingIn().OnExitTrace()()

	b, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return err
	}
	return b.Browse(path, prefix, callback)
}

// ClearBucket ...
func (l *location) ClearBucket(bucketName string, path, prefix string) error {
	if l == nil {
		return scerr.InvalidInstanceError()
	}
	if bucketName == "" {
		return scerr.InvalidParameterError("bucketName", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s', '%s')", bucketName, path, prefix), false /*Trace.Location*/).GoingIn().OnExitTrace()()

	b, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return err
	}
	return b.Clear(path, prefix)
}

// ReadObject reads the content of an object and put it in an io.Writer
func (l *location) ReadObject(bucketName, objectName string, writer io.Writer, from, to int64) error {
	if l == nil {
		return scerr.InvalidInstanceError()
	}
	if bucketName == "" {
		return scerr.InvalidParameterError("bucketName", "cannot be empty string")
	}
	if objectName == "" {
		return scerr.InvalidParameterError("objectName", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s')", bucketName, objectName), false /*Trace.Location*/).GoingIn().OnExitTrace()()

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
) (Object, error) {

	if l == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if bucketName == "" {
		return nil, scerr.InvalidParameterError("bucketName", "cannot be empty string")
	}
	if objectName == "" {
		return nil, scerr.InvalidParameterError("objectName", "cannot be empty string")
	}
	if source == nil {
		return nil, scerr.InvalidParameterError("source", "cannot be nil")
	}

	defer concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s', %d)", bucketName, objectName, size), false /*Trace.Location*/).GoingIn().OnExitTrace()()

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
) (Object, error) {

	if l == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if bucketName == "" {
		return nil, scerr.InvalidParameterError("bucketName", "cannot be empty string")
	}
	if objectName == "" {
		return nil, scerr.InvalidParameterError("objectName", "cannot be empty string")
	}

	defer concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s', %d, %d)", bucketName, objectName, sourceSize, chunkSize), false /*Trace.Location*/).GoingIn().OnExitTrace()()

	bucket, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return nil, err
	}
	return bucket.WriteMultiPartObject(objectName, source, sourceSize, chunkSize, metadata)
}
