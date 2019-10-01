package loghelpers

import (
	"fmt"

	"github.com/sirupsen/logrus"
)

const (
	outputErrorTemplate = "%s WITH ERROR [%+v]"
)

var (
	logLevelFnMap = map[logrus.Level]func(args ...interface{}){
		logrus.TraceLevel: logrus.Trace,
		logrus.DebugLevel: logrus.Debug,
		logrus.InfoLevel:  logrus.Info,
		logrus.WarnLevel:  logrus.Warn,
		logrus.ErrorLevel: logrus.Error,
	}
)

// LogErrorCallback returns a func that will log error.
// Intended to be used with defer for example
func LogErrorCallback(in string, err *error) func() {
	return func() {
		if err != nil && *err != nil {
			logrus.Error(fmt.Sprintf(outputErrorTemplate, in, *err))
		}
	}
}

// LogErrorWithLevelCallback returns a function that will log error with the log level wanted
// Intended to be used with defer for example.
func LogErrorWithLevelCallback(in string, err *error, level logrus.Level) func() {
	logLevelFn, ok := logLevelFnMap[level]
	if !ok {
		logLevelFn = logrus.Debug
	}

	return func() {
		if err != nil && *err != nil {
			logLevelFn(fmt.Sprintf(outputErrorTemplate, in, *err))
		}
	}
}

// LogTraceErrorCallback returns a function that will log error in Trace log level.
// Intended to be used with defer for example.
func LogTraceErrorCallback(in string, err *error) func() {
	return LogErrorWithLevelCallback(in, err, logrus.TraceLevel)
}
