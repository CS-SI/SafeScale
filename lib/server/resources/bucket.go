package resources

import (
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
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

	GetHost(task concurrency.Task) (string, fail.Error)
	GetMountPoint(task concurrency.Task) (string, fail.Error)
	Create(task concurrency.Task, name string) fail.Error
	Mount(task concurrency.Task, hostname string, path string) fail.Error
	Unmount(task concurrency.Task, hostname string) fail.Error
}
