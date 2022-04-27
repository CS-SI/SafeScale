package objectstorage

import (
	"io"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type locationtransparent struct {
	inner Location
}

func newlocationtransparent(inner Location) (*locationtransparent, error) {
	return &locationtransparent{inner: inner}, nil
}

func (l locationtransparent) Protocol() (string, fail.Error) {
	return l.inner.Protocol()
}

func (l locationtransparent) Configuration() (Config, fail.Error) {
	return l.inner.Configuration()
}

func (l locationtransparent) ListBuckets(s string) ([]string, fail.Error) {
	return l.inner.ListBuckets(s)
}

func (l locationtransparent) FindBucket(s string) (bool, fail.Error) {
	return l.inner.FindBucket(s)
}

func (l locationtransparent) InspectBucket(s string) (abstract.ObjectStorageBucket, fail.Error) {
	return l.inner.InspectBucket(s)
}

func (l locationtransparent) CreateBucket(s string) (abstract.ObjectStorageBucket, fail.Error) {
	return l.inner.CreateBucket(s)
}

func (l locationtransparent) DeleteBucket(s string) fail.Error {
	return l.inner.DeleteBucket(s)
}

func (l locationtransparent) HasObject(s string, s2 string) (bool, fail.Error) {
	return l.inner.HasObject(s, s2)
}

func (l locationtransparent) ClearBucket(s string, s2 string, s3 string) fail.Error {
	return l.inner.ClearBucket(s, s2, s3)
}

func (l locationtransparent) ListObjects(s string, s2 string, s3 string) ([]string, fail.Error) {
	return l.inner.ListObjects(s, s2, s3)
}

func (l locationtransparent) InvalidateObject(bucketName string, objectName string) fail.Error {
	return nil
}

func (l locationtransparent) DownloadBucket(bucketName, decryptionKey string) (_ []byte, ferr fail.Error) {
	return l.inner.DownloadBucket(bucketName, decryptionKey)
}

func (l locationtransparent) InspectObject(s string, s2 string) (abstract.ObjectStorageItem, fail.Error) {
	return l.inner.InspectObject(s, s2)
}

func (l locationtransparent) ItemEtag(bucketName, objectName string) (_ string, ferr fail.Error) {
	return l.inner.ItemEtag(bucketName, objectName)
}

func (l locationtransparent) ReadObject(s string, s2 string, writer io.Writer, i int64, i2 int64) fail.Error {
	incrementExpVar("readobject")
	incrementExpVar("metadata.reads")

	xerr := l.inner.ReadObject(s, s2, writer, i, i2)
	if xerr != nil {
		return xerr
	}

	return nil
}

func (l locationtransparent) WriteMultiPartObject(s string, s2 string, reader io.Reader, i int64, i2 int, metadata abstract.ObjectStorageItemMetadata) (abstract.ObjectStorageItem, fail.Error) {
	incrementExpVar("writeobject")
	incrementExpVar("metadata.writes")

	chunk, err := l.inner.WriteMultiPartObject(s, s2, reader, i, i2, metadata)
	if err != nil {
		return abstract.ObjectStorageItem{}, err
	}

	return chunk, nil
}

func (l locationtransparent) WriteObject(s string, s2 string, reader io.Reader, i int64, metadata abstract.ObjectStorageItemMetadata) (abstract.ObjectStorageItem, fail.Error) {
	incrementExpVar("writeobject")
	incrementExpVar("metadata.writes")

	chunk, err := l.inner.WriteObject(s, s2, reader, i, metadata)
	if err != nil {
		return abstract.ObjectStorageItem{}, err
	}

	return chunk, nil
}

func (l locationtransparent) DeleteObject(s string, s2 string) fail.Error {
	err := l.inner.DeleteObject(s, s2)
	if err != nil {
		return err
	}

	return nil
}
