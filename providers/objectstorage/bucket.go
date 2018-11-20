package objectstorage

import (
	"fmt"
	"io"
	"strings"

	"github.com/CS-SI/SafeScale/providers/model"
	log "github.com/sirupsen/logrus"

	"github.com/graymeta/stow"
)

// bucket describes a Bucket
type bucket struct {
	location  stow.Location
	container stow.Container

	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	// Host       string `json:"host,omitempty"`
	// MountPoint string `json:"mountPoint,omitempty"`
	// NbItems int `json:"nbitems,omitempty"`
}

// newBucket ...
func newBucket(location stow.Location, bucketName string) (*bucket, error) {
	if location == nil {
		panic("location is nil!")
	}
	container, err := location.Container(bucketName)
	if err == nil {
		return nil, fmt.Errorf("bucket named '%s' already exists", bucketName)
	}
	return &bucket{
		location:  location,
		container: container,
		Name:      bucketName,
	}, nil
}

// CreateObject ...
func (b *bucket) CreateObject(objectName string) (Object, error) {
	return newObject(b, objectName)
}

// GetObject ...
func (b *bucket) GetObject(objectName string) (Object, error) {
	o, err := newObject(b, objectName)
	if err != nil {
		return nil, err
	}
	if o.item == nil {
		return nil, fmt.Errorf("not found")
	}
	return o, nil
}

// ListObjects list objects of a Bucket
func (b *bucket) List(filter model.ObjectFilter) ([]string, error) {
	list := []string{}

	//log.Println("Location.Container => : ", c.Name())
	err := stow.Walk(b.container, filter.Prefix, 100,
		func(item stow.Item, err error) error {
			if err != nil {
				return err
			}
			list = append(list, item.Name())
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	return list, nil
}

// Browse walks through the objects in the Bucket and executes callback on each Object found
func (b *bucket) Browse(filter model.ObjectFilter, callback func(Object) error) error {
	err := stow.Walk(b.container, filter.Prefix, 100,
		func(item stow.Item, err error) error {
			if err != nil {
				return err
			}
			o := newObjectFromStow(b, item)
			return callback(o)
		},
	)
	return err
}

// Clear empties a bucket
func (b *bucket) Clear() error {
	return stow.Walk(b.container, stow.NoPrefix, 100,
		func(item stow.Item, err error) error {
			if err != nil {
				return err
			}
			err = b.container.RemoveItem(item.Name())
			if err != nil {
				log.Println("erreur RemoveItem => : ", err)
				return err
			}
			// l.NbItem = 0
			return err
		},
	)
}

// DeleteObject deletes an object from a bucket
func (b *bucket) DeleteObject(objectName string) error {
	o, err := newObject(b, objectName)
	if err != nil {
		return err
	}
	return o.Delete()
}

// ReadObject ...
func (b *bucket) ReadObject(objectName string, target io.Writer, ranges []model.Range) (Object, error) {
	o, err := newObject(b, objectName)
	if err != nil {
		return nil, err
	}
	err = o.Read(target, ranges)
	if err != nil {
		return nil, err
	}
	return o, nil
}

// WriteObject ...
func (b *bucket) WriteObject(objectName string, source io.Reader, sourceSize int64, metadata ObjectMetadata) (Object, error) {
	o, err := newObject(b, objectName)
	if err != nil {
		return nil, err
	}
	o.AddMetadata(metadata)
	err = o.Write(source, sourceSize)
	if err != nil {
		return nil, err
	}
	return o, nil
}

// WriteMultiPartObject ...
func (b *bucket) WriteMultiPartObject(
	objectName string,
	source io.Reader, sourceSize int64,
	chunkSize int,
	metadata ObjectMetadata,
) (Object, error) {

	o, err := newObject(b, objectName)
	if err != nil {
		return nil, err
	}
	o.AddMetadata(metadata)
	err = o.WriteMultiPart(source, sourceSize, chunkSize)
	if err != nil {
		return nil, err
	}
	return o, nil
}

// GetName returns the name of the Bucket
func (b *bucket) GetName() string {
	return b.Name
}

// GetCount returns the count of objects in the Bucket
func (b *bucket) GetCount(filter model.ObjectFilter) (int64, error) {
	log.Debugf("objectstorage.bucket.GetCount(%v) called", filter)
	defer log.Debugf("objectstorage.Location.Count(%v) done", filter)

	var count int64
	err := stow.Walk(b.container, filter.Prefix, 100,
		func(c stow.Item, err error) error {
			if err != nil {
				return err
			}
			count++
			return nil
		},
	)
	if err != nil {
		return -1, err
	}
	return count, nil
}

// GetSize returns the total size of the Objects inside the Bucket
func (b *bucket) GetSize(filter model.ObjectFilter) (int64, string, error) {
	var err error
	var vSize int64
	err = stow.Walk(b.container, filter.Prefix, 100,
		func(item stow.Item, err error) error {
			if err != nil {
				return err
			}

			sizeItem, err := item.Size()
			if err != nil {
				return err
			}
			vSize += sizeItem
			return nil
		},
	)
	if err != nil {
		return -1, "", err
	}
	return vSize, humanReadableSize(vSize), nil
}

func humanReadableSize(bytes int64) string {
	const (
		cBYTE = 1.0 << (10 * iota)
		cKILOBYTE
		cMEGABYTE
		cGIGABYTE
		cTERABYTE
		cPETABYTE
	)

	unit := ""
	value := float32(bytes)

	switch {
	case bytes >= cPETABYTE:
		unit = "P"
		value = value / cPETABYTE
	case bytes >= cTERABYTE:
		unit = "T"
		value = value / cTERABYTE
	case bytes >= cGIGABYTE:
		unit = "G"
		value = value / cGIGABYTE
	case bytes >= cMEGABYTE:
		unit = "M"
		value = value / cMEGABYTE
	case bytes >= cKILOBYTE:
		unit = "K"
		value = value / cKILOBYTE
	case bytes >= cBYTE:
		unit = "B"
	case bytes == 0:
		return "0"
	}

	stringValue := fmt.Sprintf("%.1f", value)
	stringValue = strings.TrimSuffix(stringValue, ".0")
	return fmt.Sprintf("%s%s", stringValue, unit)
}
