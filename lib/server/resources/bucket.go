package resources

import (
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
)

// Bucket defines the interface to manipulate Object Storage buckets
type Bucket interface {
	Metadata
	data.NullValue

	List(concurrency.Task) ([]string, error)
	Create(concurrency.Task, string) error
	Mount(concurrency.Task, string, string, string) error
	Unmount(concurrency.Task, string, string) error
}
