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
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/sirupsen/logrus"
	"gomodules.xyz/stow"

	// necessary for connect()
	// _ "gomodules.xyz/stow/azure"
	_ "gomodules.xyz/stow/google"
	_ "gomodules.xyz/stow/s3"
	_ "gomodules.xyz/stow/swift"

	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

//go:generate minimock -o ../mocks/mock_location.go -i github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage.Location

// FIXME: GCP Remove specific driver code

// Config ...
type Config struct {
	Type             string
	EnvAuth          bool
	AuthVersion      int
	AuthURL          string
	EndpointType     string
	Endpoint         string
	TenantDomain     string
	Tenant           string
	Domain           string
	User             string
	Key              string
	SecretKey        string
	Region           string
	AvailabilityZone string
	ProjectID        string
	Credentials      string
	BucketName       string
}

// Location ...
type Location interface {
	// ObjectStorageProtocol returns the name of the Object Storage protocol corresponding used by the location
	ObjectStorageProtocol() string

	// ListBuckets returns all bucket prefixed by a string given as a parameter
	ListBuckets(string) ([]string, fail.Error)
	// FindBucket returns true of bucket exists in stowLocation
	FindBucket(string) (bool, fail.Error)
	// InspectBucket returns info of the GetBucket
	InspectBucket(string) (abstract.ObjectStorageBucket, fail.Error)
	// CreateBucket creates a bucket
	CreateBucket(string) (abstract.ObjectStorageBucket, fail.Error)
	// DeleteBucket removes a bucket (need to be cleared before)
	DeleteBucket(string) fail.Error
	// ClearBucket empties a GetBucket
	ClearBucket(string, string, string) fail.Error

	// ListObjects lists the objects in a GetBucket
	ListObjects(string, string, string) ([]string, fail.Error)
	// InspectObject ...
	InspectObject(string, string) (abstract.ObjectStorageItem, fail.Error)
	// ReadObject ...
	ReadObject(string, string, io.Writer, int64, int64) fail.Error
	// WriteMultiPartObject ...
	WriteMultiPartObject(string, string, io.Reader, int64, int, abstract.ObjectStorageItemMetadata) (abstract.ObjectStorageItem, fail.Error)
	// WriteObject ...
	WriteObject(string, string, io.Reader, int64, abstract.ObjectStorageItemMetadata) (abstract.ObjectStorageItem, fail.Error)
	// DeleteObject delete an object from a stowContainer
	DeleteObject(string, string) fail.Error
	// FilterItemsByMetadata(ContainerName string, key string, pattern string) (map[string][]string, fail.Error)

	// // ItemSize ?
	// ItemSize(ContainerName string, item string) (int64, fail.Error)
	// // ItemEtag returns the Etag of an item
	// ItemEtag(ContainerName string, item string) (string, fail.Error)
	// // ItemLastMod returns the dagte of last update
	// ItemLastMod(ContainerName string, item string) (time.Time, fail.Error)
	// // ItemID returns the ID of the item
	// ItemID(ContainerName string, item string) (id string)
	// // ItemMetadata returns the metadata of an Item
	// ItemMetadata(ContainerName string, item string) (abstract.ObjectStorageItemMetadata, fail.Error)
}

// stowLocation ...
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

// NewLocation creates an Object Storage location based on config
func NewLocation(conf Config) (_ *location, xerr fail.Error) { // nolint
	defer fail.OnPanic(&xerr)
	l := &location{
		config: conf,
	}
	err := l.connect()
	if err != nil {
		return nil, err
	}
	return l, nil
}

// IsNull tells if the instance should be considered as a null value
func (l *location) IsNull() bool {
	return l == nil || l.stowLocation == nil
}

// Connect connects to an Object Storage location
func (l *location) connect() fail.Error {
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

	// Check config stowLocation
	err := stow.Validate(kind, config)
	if err != nil {
		logrus.Debugf("invalid config: %v", err)
		return fail.ConvertError(err)
	}
	l.stowLocation, err = stow.Dial(kind, config)
	if err != nil {
		logrus.Debugf("failed dialing stowLocation (error type=%s): %v", reflect.TypeOf(err).String(), err)
	}
	return fail.ConvertError(err)
}

// ObjectStorageProtocol returns the type of ObjectStorage
func (l location) ObjectStorageProtocol() string {
	if l.IsNull() {
		return ""
	}
	return l.config.Type
}

func (l location) estimateSize(prefix string) (int, error) {
	containerSet := make(map[string]bool) // New empty set
	currentPageSize := 10

	for {
		err := stow.WalkContainers(
			l.stowLocation, prefix, currentPageSize,
			func(c stow.Container, err error) error {
				if err != nil {
					return err
				}

				if containerSet[c.Name()] {
					return fail.DuplicateError(fmt.Sprintf("we found a duplicate: %s, we had %d items by then", c.Name(), len(containerSet)))
				}
				containerSet[c.Name()] = true

				return nil
			},
		)
		if err != nil {
			if _, ok := err.(fail.ErrDuplicate); ok { // begin again with twice the capacity
				currentPageSize = 2 * currentPageSize
				containerSet = make(map[string]bool)
				continue
			}
			return -1, err
		}
		break
	}
	return currentPageSize, nil
}

// ListBuckets ...
func (l location) ListBuckets(prefix string) (_ []string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if l.IsNull() {
		return []string{}, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("objectstorage.stowLocation"), "('%s')", prefix).Entering().Exiting()

	var list []string

	estimatedPageSize, err := l.estimateSize(prefix)
	if err != nil {
		return list, fail.ConvertError(err)
	}

	err = stow.WalkContainers(l.stowLocation, stow.NoPrefix, estimatedPageSize,
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
		return []string{}, fail.ConvertError(err)
	}
	return list, nil
}

// FindBucket returns true if a bucket with the name exists in stowLocation
func (l location) FindBucket(bucketName string) (_ bool, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if l.IsNull() {
		return false, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return false, fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("objectstorage.stowLocation"), "(%s)", bucketName).Entering().Exiting()

	found := false

	estimatedPageSize, err := l.estimateSize(stow.NoPrefix)
	if err != nil {
		return false, fail.ConvertError(err)
	}

	err = stow.WalkContainers(l.stowLocation, stow.NoPrefix, estimatedPageSize,
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
	return false, fail.ConvertError(err)
}

// InspectBucket ...
func (l location) InspectBucket(bucketName string) (_ abstract.ObjectStorageBucket, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if l.IsNull() {
		return abstract.ObjectStorageBucket{}, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return abstract.ObjectStorageBucket{}, fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("objectstorage"), "(%s)", bucketName).Entering().Exiting()

	b, err := l.inspectBucket(bucketName)
	if err != nil {
		return abstract.ObjectStorageBucket{}, err
	}
	aosb := abstract.ObjectStorageBucket{
		ID:   b.stowContainer.ID(),
		Name: bucketName,
	}
	return aosb, nil
}

// inspectBucket ...
func (l location) inspectBucket(bucketName string) (bucket, fail.Error) {
	if l.IsNull() {
		return bucket{}, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return bucket{}, fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}

	b, xerr := newBucket(l.stowLocation)
	if xerr != nil {
		return bucket{}, xerr
	}

	b.name = bucketName
	var err error
	b.stowContainer, err = l.stowLocation.Container(bucketName)
	if err != nil {
		// Note: No errors.Wrap here; error needs to be transmitted as-is
		return bucket{}, fail.ConvertError(err)
	}

	return b, nil
}

// CreateBucket ...
func (l location) CreateBucket(bucketName string) (aosb abstract.ObjectStorageBucket, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	aosb = abstract.ObjectStorageBucket{}
	if l.IsNull() {
		return aosb, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return aosb, fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("objectstorage.stowLocation"), "('%s')", bucketName).Entering().Exiting()

	c, err := l.stowLocation.CreateContainer(bucketName)
	if err != nil {
		return aosb, fail.Wrap(err, fmt.Sprintf("failure creating bucket '%s'", bucketName))
	}
	aosb = abstract.ObjectStorageBucket{
		ID:   c.ID(),
		Name: bucketName,
	}
	return aosb, nil
}

// DeleteBucket removes a bucket from Object Storage
func (l location) DeleteBucket(bucketName string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)
	if l.IsNull() {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("objectstorage.stowLocation"), "('%s')", bucketName).Entering().Exiting()

	err := l.stowLocation.RemoveContainer(bucketName)
	if err != nil {
		return fail.ConvertError(err)
	}
	return nil
}

// InspectObject ...
func (l location) InspectObject(bucketName string, objectName string) (aosi abstract.ObjectStorageItem, xerr fail.Error) {
	defer fail.OnPanic(&xerr)
	aosi = abstract.ObjectStorageItem{}
	if l.IsNull() {
		return aosi, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return aosi, fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}
	if objectName == "" {
		return aosi, fail.InvalidParameterCannotBeEmptyStringError("objectName")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("objectstorage.stowLocation"), "('%s', '%s')", bucketName, objectName).Entering().Exiting()

	b, err := l.inspectBucket(bucketName)
	if err != nil {
		return aosi, err
	}

	o, err := newObject(&b, objectName)
	if err != nil {
		return aosi, err
	}

	m, err := o.GetMetadata()
	if err != nil {
		return aosi, err
	}

	aosi = abstract.ObjectStorageItem{
		BucketName: bucketName,
		ItemName:   objectName,
		Metadata:   m,
	}
	return aosi, nil
}

// DeleteObject ...
func (l location) DeleteObject(bucketName, objectName string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)
	if l.IsNull() {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}
	if objectName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("objectName")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("objectstorage.stowLocation"), "('%s', '%s')", bucketName, objectName).Entering().Exiting()

	b, err := l.inspectBucket(bucketName)
	if err != nil {
		return err
	}
	return b.DeleteObject(objectName)
}

// ListObjects lists the objects in a GetBucket
func (l location) ListObjects(bucketName string, path, prefix string) (_ []string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)
	if l.IsNull() {
		return []string{}, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return []string{}, fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("objectstorage.stowLocation"), "('%s', '%s', '%s')", bucketName, path, prefix).Entering().Exiting()

	b, err := l.inspectBucket(bucketName)
	if err != nil {
		return nil, err
	}
	return b.ListObjects(path, prefix)
}

// BrowseBucket walks through the objects in a GetBucket and apply callback to each object
func (l location) BrowseBucket(bucketName string, path, prefix string, callback func(o Object) fail.Error) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)
	if l.IsNull() {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("objectstorage.stowLocation"), "('%s', '%s', '%s')", bucketName, path, prefix).Entering().Exiting()

	b, err := l.inspectBucket(bucketName)
	if err != nil {
		return err
	}
	return b.Browse(path, prefix, callback)
}

// ClearBucket ...
func (l location) ClearBucket(bucketName string, path, prefix string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)
	if l.IsNull() {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("objectstorage.stowLocation"), "('%s', '%s', '%s')", bucketName, path, prefix).Entering().Exiting()

	b, err := l.inspectBucket(bucketName)
	if err != nil {
		return err
	}
	return b.Clear(path, prefix)
}

// ReadObject reads the content of an object and put it in an io.Writer
func (l location) ReadObject(bucketName, objectName string, writer io.Writer, from, to int64) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)
	if l.IsNull() {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}
	if objectName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("objectName")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("objectstorage.stowLocation"), "('%s', '%s')", bucketName, objectName).Entering().Exiting()

	b, err := l.inspectBucket(bucketName)
	if err != nil {
		return err
	}

	objectName = strings.Trim(objectName, "/")
	o, err := newObject(&b, objectName)
	if err != nil {
		return err
	}

	if err = o.Read(writer, from, to); err != nil {
		return err
	}

	return nil
}

// WriteObject writes the content of reader in the Object
func (l location) WriteObject(
	bucketName string, objectName string,
	source io.Reader, size int64,
	metadata abstract.ObjectStorageItemMetadata,
) (aosi abstract.ObjectStorageItem, xerr fail.Error) {
	defer fail.OnPanic(&xerr)
	aosi = abstract.ObjectStorageItem{}
	if l.IsNull() {
		return aosi, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return aosi, fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}
	if objectName == "" {
		return aosi, fail.InvalidParameterCannotBeEmptyStringError("objectName")
	}
	if source == nil {
		return aosi, fail.InvalidParameterCannotBeNilError("source")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("objectstorage.stowLocation"), "('%s', '%s', %d)", bucketName, objectName, size).Entering().Exiting()

	b, err := l.inspectBucket(bucketName)
	if err != nil {
		if err.Error() == "not found" {
			return aosi, fail.NotFoundError("failed to find bucket '%s'", bucketName)
		}
		return aosi, err
	}

	o, err := b.WriteObject(objectName, source, size, metadata)
	if err != nil {
		return aosi, err
	}

	aosi, err = convertObjectToAbstract(o)
	if err != nil {
		return aosi, err
	}

	aosi.BucketName = bucketName
	return aosi, nil
}

// WriteMultiPartObject writes data from 'source' to an object in Object Storage, splitting data in parts of 'chunkSize' bytes
// Note: nothing to do with multi-chunk abilities of various object storage technologies
func (l location) WriteMultiPartObject(
	bucketName string, objectName string,
	source io.Reader, sourceSize int64,
	chunkSize int,
	metadata abstract.ObjectStorageItemMetadata,
) (aosi abstract.ObjectStorageItem, xerr fail.Error) {
	defer fail.OnPanic(&xerr)
	aosi = abstract.ObjectStorageItem{}
	if l.IsNull() {
		return aosi, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return aosi, fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}
	if objectName == "" {
		return aosi, fail.InvalidParameterCannotBeEmptyStringError("objectName")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("objectstorage.stowLocation"), "('%s', '%s', %d, %d)", bucketName, objectName, sourceSize, chunkSize).Entering()
	defer tracer.Exiting()

	b, err := l.inspectBucket(bucketName)
	if err != nil {
		return aosi, err
	}
	o, err := b.WriteMultiPartObject(objectName, source, sourceSize, chunkSize, metadata)
	if err != nil {
		return aosi, err
	}
	aosi, err = convertObjectToAbstract(o)
	if err != nil {
		return aosi, err
	}
	aosi.BucketName = bucketName
	return aosi, nil
}

func convertObjectToAbstract(in Object) (abstract.ObjectStorageItem, fail.Error) {
	id, err := in.GetID()
	if err != nil {
		return abstract.ObjectStorageItem{}, err
	}
	name, err := in.GetName()
	if err != nil {
		return abstract.ObjectStorageItem{}, err
	}
	m, err := in.GetMetadata()
	if err != nil {
		return abstract.ObjectStorageItem{}, err
	}
	aosi := abstract.ObjectStorageItem{
		ItemID:   id,
		ItemName: name,
		Metadata: m,
	}
	return aosi, nil
}
