package resources

import (
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
)

// Bucket defines the interface to manipulate Object Storage buckets
type Bucket interface {
	// Metadata
	data.Identifyable
	data.NullValue

	SafeGetHost() string
	SafeGetMountPoint() string
	Create(concurrency.Task, string) error
	Delete(concurrency.Task) error
	Mount(concurrency.Task, string, string) error
	Unmount(concurrency.Task, string) error
}
