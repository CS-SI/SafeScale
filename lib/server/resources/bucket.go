package resources

import (
    "github.com/CS-SI/SafeScale/lib/utils/concurrency"
    "github.com/CS-SI/SafeScale/lib/utils/data"
    "github.com/CS-SI/SafeScale/lib/utils/fail"
)

// GetBucket defines the interface to manipulate Object Storage buckets
type Bucket interface {
    Metadata
    data.Identifiable
    data.NullValue

    GetHost(concurrency.Task) (string, fail.Error)
    GetMountPoint(concurrency.Task) (string, fail.Error)
    Create(concurrency.Task, string) fail.Error
    Mount(concurrency.Task, string, string) fail.Error
    Unmount(concurrency.Task, string) fail.Error
}
