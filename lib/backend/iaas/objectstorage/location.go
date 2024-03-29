/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/crypt"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"gomodules.xyz/stow"

	// necessary for connect()
	// _ "gomodules.xyz/stow/azure"
	_ "gomodules.xyz/stow/google"
	_ "gomodules.xyz/stow/s3"
	_ "gomodules.xyz/stow/swift"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

//go:generate minimock -o ../mocks/mock_location.go -i github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage.Location

// FIXME: Make this easy to validate, what is optional ?, what is mandatory ?

// Config represents a tenant configuration
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
	DNS              string
	Direct           bool // if true, no stow cache is used
	Suffix           string
}

// Location ...
type Location interface {
	// Protocol returns the name of the Object Storage protocol corresponding used by the location
	Protocol() (string, fail.Error)
	Configuration() (Config, fail.Error) // returns the configuration used to create Location
	// ListBuckets returns all bucket prefixed by a string given as a parameter
	ListBuckets(context.Context, string) ([]string, fail.Error)
	// FindBucket returns true of bucket exists in stowLocation
	FindBucket(context.Context, string) (bool, fail.Error)
	// InspectBucket returns info of the GetBucket
	InspectBucket(context.Context, string) (abstract.ObjectStorageBucket, fail.Error)
	// CreateBucket creates a bucket
	CreateBucket(context.Context, string) (abstract.ObjectStorageBucket, fail.Error)
	// DeleteBucket removes a bucket (need to be cleared before)
	DeleteBucket(context.Context, string) fail.Error
	// DownloadBucket downloads a bucket
	DownloadBucket(ctx context.Context, bucketName, decryptionKey string) ([]byte, fail.Error)

	// UploadBucket uploads a bucket
	UploadBucket(ctx context.Context, bucketName, localDirectory string) (ferr fail.Error)

	// ClearBucket empties a Bucket
	ClearBucket(context.Context, string, string, string) fail.Error

	// ListObjects lists the objects in a Bucket
	ListObjects(context.Context, string, string, string) ([]string, fail.Error)

	// InvalidateObject ...
	InvalidateObject(context.Context, string, string) fail.Error

	// InspectObject ...
	InspectObject(context.Context, string, string) (abstract.ObjectStorageItem, fail.Error)
	// HasObject ...
	HasObject(context.Context, string, string) (bool, fail.Error)
	// ReadObject ...
	ReadObject(context.Context, string, string, io.Writer, int64, int64) (bytes.Buffer, fail.Error)
	// WriteObject ...
	WriteObject(
		context.Context, string, string, io.Reader, int64, abstract.ObjectStorageItemMetadata,
	) (abstract.ObjectStorageItem, fail.Error)
	// DeleteObject delete an object from a stowContainer
	DeleteObject(context.Context, string, string) fail.Error
	// ItemEtag returns the Etag of an item
	ItemEtag(context.Context, string, string) (string, fail.Error)

	// ItemSize ?
	// ItemSize(ContainerName string, item string) (int64, fail.Error)

	// ItemID returns the ID of the item
	// ItemID(ContainerName string, item string) (id string)

	// ItemMetadata returns the metadata of an Item
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

	currentBucketName string
	currentBucket     bucket
}

// NewLocation creates an Object Storage location based on config
func NewLocation(conf Config) (_ Location, ferr fail.Error) { // nolint
	defer fail.OnPanic(&ferr)
	l := &location{
		config: conf,
	}
	err := l.connect()
	if err != nil {
		return nil, err
	}

	if conf.Direct {
		nlt, serr := newlocationtransparent(l)
		if serr != nil {
			return nil, fail.ConvertError(serr)
		}
		return nlt, nil
	}

	nl, serr := newLocationcache(l)
	if serr != nil {
		return nil, fail.ConvertError(serr)
	}

	return nl, nil
}

// IsNull tells if the instance should be considered as a null value
func (instance *location) IsNull() bool {
	return instance == nil || instance.stowLocation == nil
}

// Connect connects to an Object Storage location
func (instance *location) connect() fail.Error {

	if instance == nil {
		return fail.InvalidInstanceError()
	}

	// FIXME: GCP Remove specific driver code, Google requires a custom cfg here..., this will require a refactoring based on stow.ConfigMap
	var config stow.ConfigMap

	if instance.config.Type == "google" {
		config = stow.ConfigMap{
			"json":       instance.config.Credentials,
			"project_id": instance.config.ProjectID,
		}
	} else {
		config = stow.ConfigMap{
			"access_key_id":   instance.config.User,
			"secret_key":      instance.config.SecretKey,
			"username":        instance.config.User,
			"key":             instance.config.SecretKey,
			"endpoint":        instance.config.Endpoint,
			"tenant_name":     instance.config.Tenant,
			"tenant_auth_url": instance.config.AuthURL,
			"region":          instance.config.Region,
			"domain":          instance.config.TenantDomain,
			"kind":            instance.config.Type,
		}
	}
	kind := instance.config.Type

	// Check config stowLocation
	err := stow.Validate(kind, config)
	if err != nil {
		return fail.ConvertError(err)
	}
	instance.stowLocation, err = stow.Dial(kind, config)
	if err != nil {
		return fail.ConvertError(err)
	}

	return nil
}

// Protocol returns the type of ObjectStorage
func (instance location) Protocol() (string, fail.Error) {
	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}
	return instance.config.Type, nil
}

// Configuration returns the configuration used to create Location
func (instance location) Configuration() (Config, fail.Error) {
	if valid.IsNil(instance) {
		return Config{}, fail.InvalidInstanceError()
	}
	return instance.config, nil
}

func (instance location) estimateSize(prefix string) (int, error) {
	containerSet := make(map[string]bool) // New empty set
	currentPageSize := 10

	for {
		err := stow.WalkContainers(
			instance.stowLocation, prefix, currentPageSize,
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
func (instance location) ListBuckets(ctx context.Context, prefix string) (_ []string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return []string{}, fail.InvalidInstanceError()
	}

	var list []string

	estimatedPageSize, err := instance.estimateSize(prefix)
	if err != nil {
		return list, fail.ConvertError(err)
	}

	err = stow.WalkContainers(instance.stowLocation, stow.NoPrefix, estimatedPageSize,
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
func (instance location) FindBucket(ctx context.Context, bucketName string) (_ bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return false, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return false, fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}

	found := false

	estimatedPageSize, err := instance.estimateSize(stow.NoPrefix)
	if err != nil {
		return false, fail.ConvertError(err)
	}

	err = stow.WalkContainers(instance.stowLocation, stow.NoPrefix, estimatedPageSize,
		func(c stow.Container, err error) error {
			if err != nil {
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
func (instance location) InspectBucket(ctx context.Context, bucketName string) (
	_ abstract.ObjectStorageBucket, ferr fail.Error,
) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return abstract.ObjectStorageBucket{}, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return abstract.ObjectStorageBucket{}, fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}

	b, err := instance.GetBucket(bucketName)
	if err != nil {
		return abstract.ObjectStorageBucket{}, err
	}
	aosb := abstract.ObjectStorageBucket{
		ID:   b.stowContainer.ID(),
		Name: bucketName,
	}
	return aosb, nil
}

// GetBucket ...
func (instance *location) GetBucket(bucketName string) (_ bucket, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return bucket{}, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return bucket{}, fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}

	if instance.currentBucketName == bucketName {
		return instance.currentBucket, nil
	}

	b, xerr := newBucket(instance.stowLocation)
	if xerr != nil {
		return bucket{}, xerr
	}

	b.name = bucketName
	var err error
	b.stowContainer, err = instance.stowLocation.Container(bucketName)
	if err != nil {
		// Note: No errors.Wrap here; error needs to be transmitted as-is
		return bucket{}, fail.ConvertError(err)
	}

	instance.currentBucket = b
	instance.currentBucketName = bucketName

	return b, nil
}

// CreateBucket ...
func (instance location) CreateBucket(ctx context.Context, bucketName string) (
	aosb abstract.ObjectStorageBucket, ferr fail.Error,
) {
	defer fail.OnPanic(&ferr)

	aosb = abstract.ObjectStorageBucket{}
	if valid.IsNil(instance) {
		return aosb, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return aosb, fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}

	c, err := instance.stowLocation.CreateContainer(bucketName)
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
func (instance location) DeleteBucket(ctx context.Context, bucketName string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}

	err := instance.stowLocation.RemoveContainer(bucketName)
	if err != nil {
		return fail.ConvertError(err)
	}
	return nil
}

func (instance location) InvalidateObject(ctx context.Context, bucketName string, objectName string) fail.Error {
	return nil
}

// InspectObject ...
func (instance location) InspectObject(
	ctx context.Context, bucketName string, objectName string,
) (aosi abstract.ObjectStorageItem, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	aosi = abstract.ObjectStorageItem{}
	if valid.IsNil(instance) {
		return aosi, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return aosi, fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}
	if objectName == "" {
		return aosi, fail.InvalidParameterCannotBeEmptyStringError("objectName")
	}

	b, err := instance.GetBucket(bucketName)
	if err != nil {
		return aosi, err
	}

	o, err := newObject(&b, objectName)
	if err != nil {
		return aosi, err
	}

	m, err := o.GetMetadata(ctx)
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
func (instance location) DeleteObject(ctx context.Context, bucketName string, objectName string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}
	if objectName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("objectName")
	}

	has, err := instance.HasObject(ctx, bucketName, objectName)
	if err != nil {
		return err
	}
	if !has {
		return nil
	}

	b, err := instance.GetBucket(bucketName)
	if err != nil {
		return err
	}
	return b.DeleteObject(ctx, objectName)
}

// ListObjects lists the objects in a GetBucket
func (instance location) ListObjects(ctx context.Context, bucketName string, path string, prefix string) (
	_ []string, ferr fail.Error,
) {
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return []string{}, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return []string{}, fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}

	b, err := instance.GetBucket(bucketName)
	if err != nil {
		return nil, err
	}
	return b.ListObjects(ctx, path, prefix)
}

// BrowseBucket walks through the objects in a GetBucket and apply callback to each object
func (instance location) BrowseBucket(
	ctx context.Context, bucketName string, path, prefix string, callback func(o Object) fail.Error,
) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}

	b, err := instance.GetBucket(bucketName)
	if err != nil {
		return err
	}
	return b.Browse(ctx, path, prefix, callback)
}

func (instance location) UploadBucket(ctx context.Context, bucketName, localDirectory string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}

	var issues []error
	err := filepath.Walk(localDirectory, func(path string, info os.FileInfo, e error) error {
		if e != nil {
			return e
		}

		// check if it is a regular file (not dir)
		if info.Mode().IsRegular() {
			fpr, err := filepath.Rel(localDirectory, path)
			if err != nil {
				issues = append(issues, err)
				return nil
			}

			fr, err := os.Open(path)
			if err != nil {
				issues = append(issues, err)
				return nil
			}

			fin, err := fr.Stat()
			if err != nil {
				issues = append(issues, err)
				return nil
			}

			_, err = instance.WriteObject(ctx, bucketName, fpr, fr, fin.Size(), nil)
			if err != nil {
				issues = append(issues, err)
				return nil
			}
		}
		return nil
	})

	if err != nil {
		return fail.ConvertError(err)
	}

	if len(issues) > 0 {
		return fail.NewErrorList(issues)
	}

	return nil
}

// DownloadBucket just downloads the bucket
func (instance location) DownloadBucket(ctx context.Context, bucketName, decryptionKey string) (
	_ []byte, ferr fail.Error,
) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}

	path := ""
	prefix := ""

	zippedBucket, err := os.CreateTemp("", "bucketcontent.*.zip")
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	defer func(closer *os.File) {
		_ = closer.Close()
		_ = os.Remove(zippedBucket.Name())
	}(zippedBucket)

	zipwriter := zip.NewWriter(zippedBucket)
	defer func(closer *zip.Writer) {
		_ = closer.Close()
	}(zipwriter)

	xerr := instance.BrowseBucket(ctx, bucketName, path, prefix, func(o Object) fail.Error {
		name, xerr := o.GetName(ctx)
		if xerr != nil {
			return xerr
		}
		name = strings.TrimPrefix(name, path)

		var buffer bytes.Buffer
		_, ierr := instance.ReadObject(ctx, bucketName, path+name, &buffer, 0, 0)
		if ierr != nil {
			return ierr
		}

		var content []byte
		if decryptionKey != "" {
			ck, err := crypt.NewEncryptionKey([]byte(decryptionKey))
			if err != nil {
				return fail.ConvertError(err)
			}
			clean, err := crypt.Decrypt(buffer.Bytes(), ck)
			if err != nil {
				return fail.ConvertError(err)
			}
			content = clean
		} else {
			content = buffer.Bytes()
		}

		tw, err := zipwriter.Create(name)
		if err != nil {
			return fail.ConvertError(err)
		}
		_, err = tw.Write(content)
		if err != nil {
			return fail.ConvertError(err)
		}

		return nil
	})
	if xerr != nil {
		return nil, xerr
	}

	_ = zipwriter.Close()
	_ = zippedBucket.Close()

	ct, err := os.ReadFile(zippedBucket.Name())
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	return ct, nil
}

// ClearBucket ...
func (instance location) ClearBucket(
	ctx context.Context, bucketName string, path string, prefix string,
) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}

	b, err := instance.GetBucket(bucketName)
	if err != nil {
		return err
	}
	return b.Clear(ctx, path, prefix)
}

func (instance location) ItemEtag(ctx context.Context, bucketName string, objectName string) (
	_ string, ferr fail.Error,
) {
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return "", fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}
	if objectName == "" {
		return "", fail.InvalidParameterCannotBeEmptyStringError("objectName")
	}

	has, err := instance.HasObject(ctx, bucketName, objectName)
	if err != nil {
		return "", err
	}
	if !has {
		return "", fail.NotFoundError("object %s not found in bucket", objectName)
	}

	b, err := instance.GetBucket(bucketName)
	if err != nil {
		return "", err
	}

	objectName = strings.Trim(objectName, "/")
	o, err := newObject(&b, objectName)
	if err != nil {
		return "", err
	}

	return o.GetETag(ctx)
}

func (instance location) HasObject(ctx context.Context, bucketName string, objectName string) (
	_ bool, ferr fail.Error,
) {
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return false, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return false, fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}
	if objectName == "" {
		return false, fail.InvalidParameterCannotBeEmptyStringError("objectName")
	}

	b, xerr := instance.GetBucket(bucketName)
	if xerr != nil {
		return false, xerr
	}

	objectName = strings.Trim(objectName, "/")
	item, err := b.stowContainer.Item(objectName)
	if err != nil {
		switch err.Error() {
		case NotFound: // this is an implementation detail of stow
			return false, nil // nolint, we get an empty object
		default:
			return false, fail.ConvertError(err)
		}
	}

	return item != nil, nil
}

// ReadObject reads the content of an object and put it in an io.Writer
func (instance location) ReadObject(ctx context.Context, bucketName string, objectName string, writer io.Writer, from int64, to int64) (i bytes.Buffer, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	if valid.IsNil(instance) {
		return bytes.Buffer{}, fail.InvalidInstanceError()
	}
	if bucketName == "" {
		return bytes.Buffer{}, fail.InvalidParameterCannotBeEmptyStringError("bucketName")
	}
	if objectName == "" {
		return bytes.Buffer{}, fail.InvalidParameterCannotBeEmptyStringError("objectName")
	}

	has, err := instance.HasObject(ctx, bucketName, objectName)
	if err != nil {
		return bytes.Buffer{}, err
	}

	if !has {
		return bytes.Buffer{}, fail.NotFoundError("object '%s' not found in bucket '%s'", objectName, bucketName)
	}

	b, err := instance.GetBucket(bucketName)
	if err != nil {
		return bytes.Buffer{}, err
	}

	objectName = strings.Trim(objectName, "/")
	o, err := newObject(&b, objectName)
	if err != nil {
		return bytes.Buffer{}, err
	}

	var buffer bytes.Buffer
	muw := io.MultiWriter(writer, &buffer)

	if err = o.Read(ctx, muw, from, to); err != nil {
		return bytes.Buffer{}, err
	}

	// logrus.Warnf("Nice: we recovered %s", buffer.String())

	return buffer, nil
}

// WriteObject writes the content of reader in the Object
func (instance location) WriteObject(
	ctx context.Context, bucketName string, objectName string, source io.Reader, size int64,
	metadata abstract.ObjectStorageItemMetadata,
) (aosi abstract.ObjectStorageItem, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	aosi = abstract.ObjectStorageItem{}
	if valid.IsNil(instance) {
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

	b, err := instance.GetBucket(bucketName)
	if err != nil {
		if err.Error() == NotFound {
			return aosi, fail.NotFoundError("failed to find bucket '%s'", bucketName)
		}
		return aosi, err
	}

	o, err := b.WriteObject(ctx, objectName, source, size, metadata)
	if err != nil {
		return aosi, err
	}

	aosi, err = convertObjectToAbstract(ctx, o)
	if err != nil {
		return aosi, err
	}

	aosi.BucketName = bucketName
	return aosi, nil
}

func convertObjectToAbstract(ctx context.Context, in Object) (abstract.ObjectStorageItem, fail.Error) {
	id, err := in.GetID(ctx)
	if err != nil {
		return abstract.ObjectStorageItem{}, err
	}
	name, err := in.GetName(ctx)
	if err != nil {
		return abstract.ObjectStorageItem{}, err
	}
	m, err := in.GetMetadata(ctx)
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
