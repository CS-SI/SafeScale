package objectstorage

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/graymeta/stow"
	log "github.com/sirupsen/logrus"
	// necessary for connect
	// _ "github.com/graymeta/stow/azure"
	// _ "github.com/graymeta/stow/google"
	_ "github.com/graymeta/stow/s3"
	_ "github.com/graymeta/stow/swift"
)

// object implementation of Object interface
type object struct {
	bucket *bucket
	item   stow.Item

	ID       string         `json:"id,omitempty"`
	Name     string         `json:"name,omitempty"`
	Metadata ObjectMetadata `json:"metadata,omitempty"`
	// DeleteAt     time.Time              `json:"delete_at,omitempty"`
	// LastModified time.Time              `json:"last_modified,omitempty"`
	// ContentType   string                 `json:"content_type,omitempty"`
	// ContentLength int64                  `json:"content_length,omitempty"`
	// ETag          string                 `json:"etag,omitempty"`
	// Size          int64                  `json:"size,omitempty"`
	// Date          time.Time              `json:"date,omitempty"`
	// Content       io.ReadSeeker          `json:"content,omitempty"`
}

// NewObject ...
func newObject(bucket *bucket, objectName string) (*object, error) {
	o := &object{
		bucket: bucket,
		Name:   objectName,
	}
	item, err := bucket.container.Item(objectName)
	if err == nil {
		o.item = item
	}
	return o, nil
}

// newObjectFromStow ...
func newObjectFromStow(bucket *bucket, item stow.Item) *object {
	if bucket == nil {
		panic("bucket is nil!")
	}
	if item == nil {
		panic("item is nil!")
	}

	return &object{
		bucket:   bucket,
		item:     item,
		Name:     item.Name(),
		Metadata: map[string]interface{}{},
	}
}

// Stored return true if the object exists in Object Storage
func (o *object) Stored() bool {
	return o.item != nil
}

// Reload reloads the data of the Object from the Object Storage
func (o *object) Reload() error {
	item, err := o.bucket.container.Item(o.Name)
	if err != nil {
		return err
	}
	return o.reloadFromItem(item)
}

// reloadFromItem reloads objet instance with stow.Item
func (o *object) reloadFromItem(item stow.Item) error {
	o.item = item
	newMetadata, err := item.Metadata()
	if err != nil {
		return err
	}
	o.Metadata = newMetadata
	return nil
}

// Read reads the content of the object from Object Storage and write it in 'target'
func (o *object) Read(target io.Writer, ranges []model.Range) error {
	var seekTo int64
	var length int64

	// 1st reload information about object, to be sure to have the last
	err := o.Reload()
	if err != nil {
		return err
	}

	size := o.GetSize()
	if size < 0 {
		return fmt.Errorf("unknown size of object")
	}

	length = size
	if ranges != nil {
		// TODO: support multiple ranges
		if ranges[0].From != nil {
			seekTo = int64(*ranges[0].From)
		}
		if ranges[0].To != nil {
			length = int64(*ranges[0].To) - seekTo
		}
	}
	// log.Printf("ExtractItem   %s.%s extracted until %d bytes to %d bytes to %s ", bucketName, objectName, seekTo, length, f.Name())

	source, err := o.item.Open()
	if err != nil {
		return err
	}
	defer source.Close()

	if seekTo == 0 && length >= size {
		_, err := io.CopyN(target, source, size)
		if err != nil {
			return err
		}
		//log.Println("Extract Item By BytesRange => ", bucketName, item.Name(), " wrote ", nbytes, " to ", f.Name())
	} else {
		buf := make([]byte, seekTo)
		if _, err := io.ReadAtLeast(source, buf, int(seekTo)); err != nil {
			log.Fatal(err)
		}

		bufbis := make([]byte, length)
		if _, err := io.ReadAtLeast(source, bufbis, int(length)); err != nil {
			log.Println("error ")
			log.Fatal(err)
		}

		readerbis := bytes.NewReader(bufbis)
		_, err := io.CopyBuffer(target, readerbis, bufbis)
		if err != nil {
			return err
		}
	}
	return nil
}

// Write the source to the object in Object Storage
func (o *object) Write(source io.Reader, sourceSize int64) error {
	log.Debugf("objectstorage.object<%s,%s>.Write() called", o.bucket.Name, o.Name)
	defer log.Debugf("objectstorage.object<%s,%s>.Write() done", o.bucket.Name, o.Name)

	if o.bucket == nil {
		panic("o.bucket == nil!")
	}
	item, err := o.bucket.container.Put(o.Name, source, sourceSize, o.GetMetadata())
	if err != nil {
		return err
	}
	return o.reloadFromItem(item)
}

// WriteMultiPart writes big data to Object, by parts (also called chunks)
func (o *object) WriteMultiPart(source io.Reader, sourceSize int64, chunkSize int) error {
	log.Debugf("objectstorage.object<%s,%s>.WriteMultiPart() called", o.bucket.Name, o.Name)
	defer log.Debugf("objectstorage.object<%s,%s>.WriteMultiPart() done", o.bucket.Name, o.Name)

	metadataCopy := o.GetMetadata().Clone()

	var chunkIndex int
	remaining := sourceSize
	for {
		if remaining < int64(chunkSize) {
			chunkSize = int(remaining)
		}
		err := writeChunk(o.bucket.container, o.Name, source, chunkSize, metadataCopy, chunkIndex)
		if err != nil {
			return err
		}
		remaining -= int64(chunkSize)
		// client.NbItem = client.NbItem + 1
		if remaining <= 0 {
			break
		}
		chunkIndex++
	}
	return nil
}

// writeChunk writes a chunk of data for object
func writeChunk(
	container stow.Container, objectName string,
	source io.Reader, nBytesToRead int,
	metadata ObjectMetadata,
	chunkIndex int,
) error {

	buf := make([]byte, nBytesToRead)
	nBytesRead, err := source.Read(buf)
	if err == io.EOF {
		return err
	}
	r := bytes.NewReader(buf)
	objectNamePart := objectName + strconv.Itoa(chunkIndex)
	metadata["Split"] = objectName
	_, err = container.Put(objectNamePart, r, int64(nBytesRead), metadata)
	if err != nil {
		return err
	}
	log.Debugf("written chunk #%d (%d bytes) of data in object '%s:%s'", nBytesRead, chunkIndex, container.Name(), objectName)
	return err
}

// Delete deletes the object from Object Storage
func (o *object) Delete() error {
	if o.item == nil {
		panic("o.item is nil!")
	}
	err := o.bucket.container.RemoveItem(o.Name)
	if err != nil {
		return err
	}
	o.item = nil
	return nil
}

// ForceAddMetadata overwrites the metadata entries of the object by the ones provided in parameter
func (o *object) ForceAddMetadata(newMetadata ObjectMetadata) {
	for k, v := range newMetadata {
		o.Metadata[k] = v
	}
}

// AddMetadata adds missing entries in object metadata
func (o *object) AddMetadata(newMetadata ObjectMetadata) {
	for k, v := range newMetadata {
		_, found := o.Metadata[k]
		if !found {
			o.Metadata[k] = v
		}
	}
}

// ReplaceMetadata replaces object metadata with the ones provided in parameter
func (o *object) ReplaceMetadata(newMetadata ObjectMetadata) {
	o.Metadata = newMetadata
}

// GetName returns the name of the object
func (o *object) GetName() string {
	return o.Name
}

// GetLastUpdate returns the date of last update
func (o *object) GetLastUpdate() (time.Time, error) {
	if o.item != nil {
		return o.item.LastMod()
	}
	return time.Now(), fmt.Errorf("object metadata not found")
}

// GetMetadata returns the metadata of the object in Object Storage
func (o *object) GetMetadata() ObjectMetadata {
	return o.Metadata.Clone()
}

// GetSize returns the size of the content of the object
func (o *object) GetSize() int64 {
	if o.item != nil {
		size, err := o.item.Size()
		if err == nil {
			return size
		}
	}
	return -1
}

// GetETag returns the value of the ETag (+/- md5sum of the content...)
func (o *object) GetETag() string {
	if o.item != nil {
		etag, err := o.item.ETag()
		if err == nil {
			return etag
		}
	}
	return ""
}

// GetID ...
func (o *object) GetID() string {
	if o.item != nil {
		return o.item.ID()
	}
	return ""
}
