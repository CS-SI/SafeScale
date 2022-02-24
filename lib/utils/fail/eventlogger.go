//go:build !debug
// +build !debug

package fail

import "github.com/sirupsen/logrus"

func getEventLogger() func(format string, args ...interface{}) {
	return logrus.Errorf
}
