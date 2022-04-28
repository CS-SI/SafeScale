//go:build debug && !test
// +build debug,!test

package fail

import "github.com/sirupsen/logrus"

func getEventLogger() func(format string, args ...interface{}) {
	return logrus.Fatalf
}
