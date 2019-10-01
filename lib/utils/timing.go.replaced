package utils

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"time"
)

// Timer is a helper function to help log the time spend in a function call
func Timer(in string) func() {
	logrus.Info(in)
	start := time.Now()
	return func() { logrus.Info(fmt.Sprintf("%s... finished in: [%s]", in, FmtDuration(time.Since(start)))) }
}

// TimerErr is a helper function to help log the time spend in a function call and log its failure if any
func TimerErr(in string, err *error) func() {
	logrus.Info(in)
	start := time.Now()
	return func() {
		if err == nil || (err != nil && *err == nil) {
			logrus.Info(fmt.Sprintf("%s... finished in: [%s]", in, FmtDuration(time.Since(start))))
		} else {
			logrus.Error(fmt.Sprintf("%s... finished WITH ERROR [%+v] in: %s", in, *err, FmtDuration(time.Since(start))))
		}
	}
}

// TraceOnExitErr is a helper function to help log a function failure if any
func TraceOnExitErr(in string, err *error) func() {
	return func() {
		if !(err == nil || (err != nil && *err == nil)) {
			logrus.Error(fmt.Sprintf("%s... finished WITH ERROR [%+v]", in, *err))
		}
	}
}

// TraceOnExitErrAsTrace is a helper function to help log (with minimum level) a function failure if any
func TraceOnExitErrAsTrace(in string, err *error) func() {
	return func() {
		if !(err == nil || (err != nil && *err == nil)) {
			logrus.Trace(fmt.Sprintf("%s... finished WITH ERROR [%+v]", in, *err))
		}
	}
}

// TraceOnExitErrAsLevel is a helper function to help log (with level 'level') a function failure if any
func TraceOnExitErrAsLevel(in string, err *error, level logrus.Level) func() {
	return func() {
		if !(err == nil || (err != nil && *err == nil)) {
			msg := fmt.Sprintf("%s... finished WITH ERROR [%+v]", in, *err)
			switch level {
			case logrus.TraceLevel:
				logrus.Trace(msg)
			case logrus.DebugLevel:
				logrus.Debug(msg)
			case logrus.InfoLevel:
				logrus.Info(msg)
			case logrus.WarnLevel:
				logrus.Warn(msg)
			case logrus.ErrorLevel:
				logrus.Error(msg)
			default:
				logrus.Warn(msg)
			}
		}
	}
}

// TimerWithLevel is a helper function to help log the time spend in a function call with log level 'level'
func TimerWithLevel(in string, level logrus.Level) func() {
	switch level {
	case logrus.TraceLevel:
		logrus.Trace(in)
		start := time.Now()
		return func() { logrus.Trace(fmt.Sprintf("%s... finished in: [%s]", in, FmtDuration(time.Since(start)))) }
	case logrus.DebugLevel:
		logrus.Debug(in)
		start := time.Now()
		return func() { logrus.Debug(fmt.Sprintf("%s... finished in: [%s]", in, FmtDuration(time.Since(start)))) }
	case logrus.InfoLevel:
		logrus.Info(in)
		start := time.Now()
		return func() { logrus.Info(fmt.Sprintf("%s... finished in: [%s]", in, FmtDuration(time.Since(start)))) }
	case logrus.WarnLevel:
		logrus.Warn(in)
		start := time.Now()
		return func() { logrus.Warn(fmt.Sprintf("%s... finished in: [%s]", in, FmtDuration(time.Since(start)))) }
	case logrus.ErrorLevel:
		logrus.Error(in)
		start := time.Now()
		return func() { logrus.Error(fmt.Sprintf("%s... finished in: [%s]", in, FmtDuration(time.Since(start)))) }
	default:
		logrus.Debug(in)
		start := time.Now()
		return func() { logrus.Debug(fmt.Sprintf("%s... finished in: [%s]", in, FmtDuration(time.Since(start)))) }
	}
}

// TimerErrWithLevel is a helper function to help log (with level 'level') the time spend in a function call and log (with level ERROR) its failure if any
func TimerErrWithLevel(in string, err *error, level logrus.Level) func() {
	switch level {
	case logrus.DebugLevel:
		logrus.Debug(in)
		start := time.Now()
		return func() {
			if err == nil || (err != nil && *err == nil) {
				logrus.Debug(fmt.Sprintf("%s... finished in: [%s]", in, FmtDuration(time.Since(start))))
			} else {
				logrus.Error(fmt.Sprintf("%s... finished WITH ERROR [%+v] in: %s", in, *err, FmtDuration(time.Since(start))))
			}
		}
	case logrus.InfoLevel:
		logrus.Info(in)
		start := time.Now()
		return func() {
			if err == nil || (err != nil && *err == nil) {
				logrus.Info(fmt.Sprintf("%s... finished in: [%s]", in, FmtDuration(time.Since(start))))
			} else {
				logrus.Error(fmt.Sprintf("%s... finished WITH ERROR [%+v] in: %s", in, *err, FmtDuration(time.Since(start))))
			}
		}
	case logrus.WarnLevel:
		logrus.Warn(in)
		start := time.Now()
		return func() {
			if err == nil || (err != nil && *err == nil) {
				logrus.Warn(fmt.Sprintf("%s... finished in: [%s]", in, FmtDuration(time.Since(start))))
			} else {
				logrus.Error(fmt.Sprintf("%s... finished WITH ERROR [%+v] in: %s", in, *err, FmtDuration(time.Since(start))))
			}
		}
	case logrus.ErrorLevel:
		logrus.Error(in)
		start := time.Now()
		return func() {
			if err == nil || (err != nil && *err == nil) {
				logrus.Error(fmt.Sprintf("%s... finished in: [%s]", in, FmtDuration(time.Since(start))))
			} else {
				logrus.Error(fmt.Sprintf("%s... finished WITH ERROR [%+v] in: %s", in, *err, FmtDuration(time.Since(start))))
			}
		}
	case logrus.TraceLevel:
		logrus.Trace(in)
		start := time.Now()
		return func() {
			if err == nil || (err != nil && *err == nil) {
				logrus.Trace(fmt.Sprintf("%s... finished in: [%s]", in, FmtDuration(time.Since(start))))
			} else {
				logrus.Error(fmt.Sprintf("%s... finished WITH ERROR [%+v] in: %s", in, *err, FmtDuration(time.Since(start))))
			}
		}
	default:
		logrus.Debug(in)
		start := time.Now()
		return func() {
			if err == nil || (err != nil && *err == nil) {
				logrus.Debug(fmt.Sprintf("%s... finished in: [%s]", in, FmtDuration(time.Since(start))))
			} else {
				logrus.Error(fmt.Sprintf("%s... finished WITH ERROR [%+v] in: %s", in, *err, FmtDuration(time.Since(start))))
			}
		}
	}
}

// FmtDuration is the default duration formatter used by SafeScale
func FmtDuration(dur time.Duration) string {
	ms := (dur.Nanoseconds() % 1000000000) / 1000000
	if ms == 0 {
		if dur.Nanoseconds()/1000000000 == 0 {
			ms = 1
			return fmt.Sprintf("%d ms", ms)
		}
	}

	sec := int64(dur.Truncate(time.Second).Seconds()) % 60
	min := int64(dur.Truncate(time.Minute).Minutes())

	if min == 0 {
		return fmt.Sprintf("%d seconds, %d ms", sec, ms)
	}

	return fmt.Sprintf("%d minutes, %d seconds, %d ms", min, sec, ms)
}
