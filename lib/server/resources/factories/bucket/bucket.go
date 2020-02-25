package bucket

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	objectstorageops "github.com/CS-SI/SafeScale/lib/server/resources/operations/objectstorage"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// List retrieves all available buckets
func List(svc iaas.Service) ([]string, error) {
	if svc == nil {
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}

	// tracer := concurrency.NewTracer(task, "", false).Entering()
	// defer tracer.OnExitTrace()()
	// defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	return svc.ListBuckets(objectstorage.RootPath)
}

// New instanciates a new bucket instance
func New(svc iaas.Service) (resources.Bucket, error) {
	if svc == nil {
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}
	return objectstorageops.New(svc)
}

// Load initializes the bucket with metadata from provider
func Load(svc iaas.Service, name string) (resources.Bucket, error) {
	if svc == nil {
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be emtpy string")
	}
	return objectstorageops.Load(svc, name)
}
