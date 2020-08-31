package utils

import (
    "fmt"
    "os"
    "reflect"

    "github.com/sirupsen/logrus"
)

// LazyRemove is identical to os.Remove, but doesn't raise an error, and
// log.Warn every error except "file not found" which is ignored
func LazyRemove(path string) error {
    err := os.Remove(path)
    if err != nil {
        switch err.(type) {
        case *os.PathError:
            // File not found, that's ok because we wanted to remove it...
        default:
            logrus.Errorf("LazyRemove(): err is type '%s'\n", reflect.TypeOf(err).String())
            return fmt.Errorf("error removing file '%s': %v", path, err)
        }
    }
    return nil
}
