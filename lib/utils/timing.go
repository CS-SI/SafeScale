package utils

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"time"
)

func Timer(in string) func() {
	logrus.Info(in)
	start := time.Now()
	return func() { logrus.Info(fmt.Sprintf("%s... finished in: [%s]", in, FmtDuration(time.Since(start)))) }
}

func TimerErr(in string, err *error) func() {
	logrus.Info(in)
	start := time.Now()
	return func() {
		if err == nil || (err != nil && *err == nil){
			logrus.Info(fmt.Sprintf("%s... finished in: [%s]", in, FmtDuration(time.Since(start))))
		} else {
			logrus.Error(fmt.Sprintf("%s... finished WITH ERROR [%+v] in: %s", in, *err, FmtDuration(time.Since(start))))
		}
	}
}

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

func TimerErrWithLevel(in string, err *error, level logrus.Level) func() {
	switch level {
	case logrus.DebugLevel:
		logrus.Debug(in)
		start := time.Now()
		return func() {
			if err == nil || (err != nil && *err == nil){
				logrus.Debug(fmt.Sprintf("%s... finished in: [%s]", in, FmtDuration(time.Since(start))))
			} else {
				logrus.Error(fmt.Sprintf("%s... finished WITH ERROR [%+v] in: %s", in, *err, FmtDuration(time.Since(start))))
			}
		}
	case logrus.InfoLevel:
		logrus.Info(in)
		start := time.Now()
		return func() {
			if err == nil || (err != nil && *err == nil){
				logrus.Info(fmt.Sprintf("%s... finished in: [%s]", in, FmtDuration(time.Since(start))))
			} else {
				logrus.Error(fmt.Sprintf("%s... finished WITH ERROR [%+v] in: %s", in, *err, FmtDuration(time.Since(start))))
			}
		}
	case logrus.WarnLevel:
		logrus.Warn(in)
		start := time.Now()
		return func() {
			if err == nil || (err != nil && *err == nil){
				logrus.Warn(fmt.Sprintf("%s... finished in: [%s]", in, FmtDuration(time.Since(start))))
			} else {
				logrus.Error(fmt.Sprintf("%s... finished WITH ERROR [%+v] in: %s", in, *err, FmtDuration(time.Since(start))))
			}
		}
	case logrus.ErrorLevel:
		logrus.Error(in)
		start := time.Now()
		return func() {
			if err == nil || (err != nil && *err == nil){
				logrus.Error(fmt.Sprintf("%s... finished in: [%s]", in, FmtDuration(time.Since(start))))
			} else {
				logrus.Error(fmt.Sprintf("%s... finished WITH ERROR [%+v] in: %s", in, *err, FmtDuration(time.Since(start))))
			}
		}
	case logrus.TraceLevel:
		logrus.Trace(in)
		start := time.Now()
		return func() {
			if err == nil || (err != nil && *err == nil){
				logrus.Trace(fmt.Sprintf("%s... finished in: [%s]", in, FmtDuration(time.Since(start))))
			} else {
				logrus.Error(fmt.Sprintf("%s... finished WITH ERROR [%+v] in: %s", in, *err, FmtDuration(time.Since(start))))
			}
		}
	default:
		logrus.Debug(in)
		start := time.Now()
		return func() {
			if err == nil || (err != nil && *err == nil){
				logrus.Debug(fmt.Sprintf("%s... finished in: [%s]", in, FmtDuration(time.Since(start))))
			} else {
				logrus.Error(fmt.Sprintf("%s... finished WITH ERROR [%+v] in: %s", in, *err, FmtDuration(time.Since(start))))
			}
		}
	}
}

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
