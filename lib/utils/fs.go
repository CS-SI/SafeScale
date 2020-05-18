package utils

import (
	"os"
	"reflect"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/sirupsen/logrus"
)

// LazyRemove is identical to os.Remove, but doesn't raise an error, and
// log.Warn every error except "file not found" which is ignored
func LazyRemove(path string) fail.Error {
	err := os.Remove(path)
	if err != nil {
		switch err.(type) {
		case *os.PathError:
			// File not found, that's ok because we wanted to remove it...
		default:
			logrus.Errorf("LazyRemove(): err is type '%s'", reflect.TypeOf(err).String())
			return fail.Wrap(err, "failed to remove file '%s'", path)
		}
	}
	return nil
}
