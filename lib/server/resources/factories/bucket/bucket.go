package bucket

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// List retrieves all available buckets
func List(svc iaas.Service) ([]string, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	// tracer := debug.NewTracer(task, "", false).Entering()
	// defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())
	return svc.ListBuckets(objectstorage.RootPath)
}

// New instanciates a new bucket instance
func New(svc iaas.Service) (resources.Bucket, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}
	return operations.NewBucket(svc)
}

// Load initializes the bucket with metadata from provider
func Load(task concurrency.Task, svc iaas.Service, name string) (resources.Bucket, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be emtpy string")
	}

	if task != nil {
		if task.Aborted() {
			return nil, fail.AbortedError(nil, "aborted")
		}
	}

	return operations.LoadBucket(task, svc, name)
}
