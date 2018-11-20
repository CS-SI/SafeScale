package objectstorage

import (
	"fmt"
	"io"

	"github.com/CS-SI/SafeScale/providers/model"
	log "github.com/sirupsen/logrus"

	"github.com/graymeta/stow"
	// necessary for connect
	// _ "github.com/graymeta/stow/azure"
	// _ "github.com/graymeta/stow/google"
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
func NewLocation(conf Config) Location {
	return &location{
		config: conf,
	}
}

func (l *location) getStowLocation() stow.Location {
	return l.stowLocation
}

// Connect connects to an Object Storage Location
func (l *location) Connect() error {
	log.Debugln("objectstorage.Location.Connect() called")
	defer log.Debugln("objectstorage.Location.Connect() done")

	config := stow.ConfigMap{
		"access_key_id":   l.config.Key,
		"secret_key":      l.config.Secretkey,
		"username":        l.config.User,
		"key":             l.config.Key,
		"endpoint":        l.config.Endpoint,
		"tenant_name":     l.config.Tenant,
		"tenant_auth_url": l.config.Auth,
		"region":          l.config.Region,
		"domain":          l.config.Domain,
		"kind":            l.config.Types,
	}
	kind := l.config.Types

	// Check config location
	err := stow.Validate(kind, config)
	if err != nil {
		log.Debugf("invalid config: %v", err)
		return err
	}
	l.stowLocation, err = stow.Dial(kind, config)
	if err != nil {
		log.Debugf("failed dialing location: %v", err)
	}
	return err
}

// ListBuckets ...
func (l *location) ListBuckets() ([]string, error) {
	log.Debugf("objectstorage.Location.ListBuckets() called")
	defer log.Debugf("objectstorage.Location.ListBuckets() done")

	// log.Println("Stow ListContainers Region ", client.Region)
	// log.Println("Stow ListContainers TenantName ", client.TenantName)
	vsf := []string{}
	err := stow.WalkContainers(l.stowLocation, stow.NoPrefix, 100,
		func(c stow.Container, err error) error {
			if err != nil {
				return err
			}

			vsf = append(vsf, c.Name())
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	return vsf, nil
}

// findBucket returns true if a bucket with the name exists in location
func (l *location) FindBucket(bucketName string) (bool, error) {
	log.Debugf("objectstorage.Location.FindBucket(%s) called", bucketName)
	defer log.Debugf("objectstorage.Location.ListBuckets(%s) done", bucketName)

	found := false
	err := stow.WalkContainers(l.stowLocation, stow.NoPrefix, 100,
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
	return false, err
}

// GetBucket ...
func (l *location) GetBucket(bucketName string) (Bucket, error) {
	log.Debugf("objectstorage.Location.GetBucket(%s) called", bucketName)
	defer log.Debugf("objectstorage.Location.ListBuckets(%s) done", bucketName)

	return newBucket(l.stowLocation, bucketName)
}

// CreateBucket ...
func (l *location) CreateBucket(bucketName string) (Bucket, error) {
	log.Debugf("objectstorage.Location.CreateBucket(%s) called", bucketName)
	defer log.Debugf("objectstorage.Location.CreateBucket(%s) done", bucketName)

	c, err := l.stowLocation.CreateContainer(bucketName)
	if err != nil {
		return nil, err
	}
	return &bucket{
		location: l.stowLocation,
		ID:       c.ID(),
		Name:     c.Name(),
	}, nil
}

// DeleteBucket removes a bucket from Object Storage
func (l *location) DeleteBucket(bucketName string) error {
	log.Debugf("objectstorage.Location.Delete(%s) called", bucketName)
	defer log.Debugf("objectstorage.Location.Delete(%s) done", bucketName)

	return l.stowLocation.RemoveContainer(bucketName)
}

// GetObject ...
func (l *location) GetObject(bucketName string, objectName string) (Object, error) {
	bucket, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return nil, err
	}
	return newObject(bucket, objectName)
}

// DeleteObject ...
func (l *location) DeleteObject(bucketName, objectName string) error {
	bucket, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return err
	}
	return bucket.DeleteObject(objectName)
}

// ListObjects lists the objects in a Bucket
func (l *location) ListObjects(bucketName string, filter model.ObjectFilter) ([]string, error) {
	b, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return nil, err
	}
	return b.List(filter)
}

// Browse walks through the objects in a Bucket and apply callback to each object
func (l *location) BrowseBucket(bucketName string, filter model.ObjectFilter, callback func(o Object) error) error {
	b, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return err
	}
	return b.Browse(filter, callback)
}

// ClearBucket ...
func (l *location) ClearBucket(bucketName string) error {
	log.Debugf("objectstorage.Location.ClearBucket(%s) called", bucketName)
	defer log.Debugf("objectstorage.Location.ClearBucket(%s) done", bucketName)

	b, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return err
	}
	return b.Clear()
}

// ReadObject reads the content of an object and put it in an io.Writer
func (l *location) ReadObject(bucketName, objectName string, writer io.Writer, ranges []model.Range) error {
	b, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return err
	}
	o, err := newObject(b, objectName)
	if err != nil {
		return err
	}
	err = o.Read(writer, ranges)
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

	log.Debugf("objectstorage.Location.WriteObject(%s, %s) called", bucketName, objectName)
	defer log.Debugf("objectstorage.Location.WriteObject(%s, %s) done", bucketName, objectName)

	b, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return nil, err
	}
	return b.WriteObject(objectName, source, size, metadata)
}

// WriteMultiPartObject writes data from 'source' to an object in Object Storage, splitting data in parts of 'chunkSize' bytes
func (l *location) WriteMultiPartObject(
	bucketName string, objectName string,
	source io.Reader, sourceSize int64,
	chunkSize int,
	metadata ObjectMetadata,
) (Object, error) {

	log.Debugf("objectstorage.Location.WriteMultiChunkObject(%s, %s) called", bucketName, objectName)
	defer log.Debugf("objectstorage.Location.WriteMultiChunkObject(%s, %s) called", bucketName, objectName)

	bucket, err := newBucket(l.stowLocation, bucketName)
	if err != nil {
		return nil, err
	}
	return bucket.WriteMultiPartObject(objectName, source, sourceSize, chunkSize, metadata)
}
