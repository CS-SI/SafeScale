package resources

import (
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// Bucket defines the interface to manipulate Object Storage buckets
type Bucket interface {
	// Metadata
	data.Identifiable
	data.NullValue

	SafeGetHost() string
	SafeGetMountPoint() string
	Create(concurrency.Task, string) fail.Error
	Delete(concurrency.Task) fail.Error
	Mount(concurrency.Task, string, string) fail.Error
	Unmount(concurrency.Task, string) fail.Error
}
