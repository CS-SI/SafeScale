package resources

import "github.com/CS-SI/SafeScale/lib/utils/concurrency"

// Bucket defines the interface to manipulate Object Storage buckets
type Bucket interface {
	Metadata

	List(concurrency.Task) ([]string, error)
	Create(concurrency.Task, string) error
	Mount(concurrency.Task, string, string, string) error
	Unmount(concurrency.Task, string, string) error
}
