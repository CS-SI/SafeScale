package objectstorage

import (
	"context"
	"io"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
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

func (l locationtransparent) ListBuckets(ctx context.Context, s string) ([]string, fail.Error) {
	return l.inner.ListBuckets(ctx, s)
}

func (l locationtransparent) FindBucket(ctx context.Context, s string) (bool, fail.Error) {
	return l.inner.FindBucket(ctx, s)
}

func (l locationtransparent) InspectBucket(ctx context.Context, s string) (abstract.ObjectStorageBucket, fail.Error) {
	return l.inner.InspectBucket(ctx, s)
}

func (l locationtransparent) CreateBucket(ctx context.Context, s string) (abstract.ObjectStorageBucket, fail.Error) {
	return l.inner.CreateBucket(ctx, s)
}

func (l locationtransparent) DeleteBucket(ctx context.Context, s string) fail.Error {
	return l.inner.DeleteBucket(ctx, s)
}

func (l locationtransparent) HasObject(ctx context.Context, s string, s2 string) (bool, fail.Error) {
	return l.inner.HasObject(ctx, s, s2)
}

func (l locationtransparent) ClearBucket(ctx context.Context, s string, s2 string, s3 string) fail.Error {
	return l.inner.ClearBucket(ctx, s, s2, s3)
}

func (l locationtransparent) ListObjects(ctx context.Context, s string, s2 string, s3 string) ([]string, fail.Error) {
	return l.inner.ListObjects(ctx, s, s2, s3)
}

func (l locationtransparent) InvalidateObject(ctx context.Context, bucketName string, objectName string) fail.Error {
	return l.inner.InvalidateObject(ctx, bucketName, objectName)
}

func (l locationtransparent) UploadBucket(ctx context.Context, bucketName, localDirectory string) (ferr fail.Error) {
	return l.inner.UploadBucket(ctx, bucketName, localDirectory)
}

func (l locationtransparent) DownloadBucket(ctx context.Context, bucketName, decryptionKey string) (_ []byte, ferr fail.Error) {
	return l.inner.DownloadBucket(ctx, bucketName, decryptionKey)
}

func (l locationtransparent) InspectObject(ctx context.Context, s string, s2 string) (abstract.ObjectStorageItem, fail.Error) {
	return l.inner.InspectObject(ctx, s, s2)
}

func (l locationtransparent) ItemEtag(ctx context.Context, bucketName string, objectName string) (_ string, ferr fail.Error) {
	return l.inner.ItemEtag(ctx, bucketName, objectName)
}

func (l locationtransparent) ReadObject(ctx context.Context, s string, s2 string, writer io.Writer, i int64, i2 int64) fail.Error {
	incrementExpVar("readobject")
	incrementExpVar("metadata.reads")

	xerr := l.inner.ReadObject(ctx, s, s2, writer, i, i2)
	if xerr != nil {
		return xerr
	}

	return nil
}

func (l locationtransparent) WriteMultiPartObject(ctx context.Context, s string, s2 string, reader io.Reader, i int64, i2 int, metadata abstract.ObjectStorageItemMetadata) (abstract.ObjectStorageItem, fail.Error) {
	incrementExpVar("writeobject")
	incrementExpVar("metadata.writes")

	chunk, err := l.inner.WriteMultiPartObject(ctx, s, s2, reader, i, i2, metadata)
	if err != nil {
		return abstract.ObjectStorageItem{}, err
	}

	return chunk, nil
}

func (l locationtransparent) WriteObject(ctx context.Context, s string, s2 string, reader io.Reader, i int64, metadata abstract.ObjectStorageItemMetadata) (abstract.ObjectStorageItem, fail.Error) {
	incrementExpVar("writeobject")
	incrementExpVar("metadata.writes")

	chunk, err := l.inner.WriteObject(ctx, s, s2, reader, i, metadata)
	if err != nil {
		return abstract.ObjectStorageItem{}, err
	}

	return chunk, nil
}

func (l locationtransparent) DeleteObject(ctx context.Context, s string, s2 string) fail.Error {
	err := l.inner.DeleteObject(ctx, s, s2)
	if err != nil {
		return err
	}

	return nil
}
