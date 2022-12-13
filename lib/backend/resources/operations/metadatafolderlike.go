package operations

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

//go:generate minimock -o ../mocks/mock_mdf.go -i github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations.MetadataFolderLike

type MetadataFolderLike interface {
	IsNull() bool
	Service() iaas.Service
	GetBucket(ctx context.Context) (abstract.ObjectStorageBucket, fail.Error)
	Path() string
	Lookup(ctx context.Context, path string, name string) fail.Error
	Delete(ctx context.Context, path string, name string) fail.Error
	Read(ctx context.Context, path string, name string, callback func([]byte) fail.Error, options ...data.ImmutableKeyValue) fail.Error
	Write(ctx context.Context, path string, name string, content []byte, options ...data.ImmutableKeyValue) fail.Error
	Browse(ctx context.Context, path string, callback FolderDecoderCallback) fail.Error
}
