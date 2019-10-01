package loghelpers

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
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

// LogErrorCallback returns a func that'll log error
func LogErrorCallback(in string, tracer *concurrency.Tracer, err *error) func() {
	if tracer != nil {
		tracer.In()
	}

	// in the meantime if 'in' is empty, recover function name from caller
	if len(in) == 0 {
		if pc, _, _, ok := runtime.Caller(1); ok {
			if f := runtime.FuncForPC(pc); f != nil {
				in = filepath.Base(f.Name())
			}
		}
	}

	return func() {
		if err != nil && *err != nil {
			logrus.Error(fmt.Sprintf(outputErrorTemplate, in, *err))
		}
		if tracer != nil {
			tracer.Out()
		}
	}
}

// LogTraceErrorCallback ...
func LogTraceErrorCallback(in string, tracer *concurrency.Tracer, err *error) func() {
	return LogErrorWithLevelCallback(in, tracer, err, logrus.TraceLevel)
}

// LogErrorWithLevelCallback returns a function that'll log error with the log level wanted
func LogErrorWithLevelCallback(in string, tracer *concurrency.Tracer, err *error, level logrus.Level) func() {
	logLevelFn, ok := logLevelFnMap[level]
	if !ok {
		logLevelFn = logrus.Debug
	}

	if tracer != nil {
		tracer.In()
	}

	// in the meantime if 'in' is empty, recover function name from caller
	if len(in) == 0 {
		if pc, _, _, ok := runtime.Caller(1); ok {
			if f := runtime.FuncForPC(pc); f != nil {
				in = filepath.Base(f.Name())
			}
		}
	}

	return func() {
		if err != nil && *err != nil {
			logLevelFn(fmt.Sprintf(outputErrorTemplate, in, *err))
		}
		if tracer != nil {
			tracer.Out()
		}
	}
}
