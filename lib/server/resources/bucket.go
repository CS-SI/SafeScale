package resources

import (
	"context"

	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/cache"
	"github.com/CS-SI/SafeScale/lib/utils/data/observer"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// Bucket GetBucket defines the interface to manipulate Object Storage buckets
type Bucket interface {
	Metadata
	data.Identifiable
	cache.Cacheable
	observer.Observable

	GetHost(ctx context.Context) (string, fail.Error)
	GetMountPoint(ctx context.Context) (string, fail.Error)
	Create(ctx context.Context, name string) fail.Error
	Mount(ctx context.Context, hostname string, path string) fail.Error
	Unmount(ctx context.Context, hostname string) fail.Error
}
