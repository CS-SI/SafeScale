/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package commonlog

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

var (
	pidMaxLength int

	// baseTimestamp time.Time
	// emptyFieldMap logrus.FieldMap

	// LogLevelFnMap is a map between loglevel and log functions from logrus
	LogLevelFnMap = func(ctx context.Context, lev logrus.Level) func(args ...interface{}) {
		lm := map[logrus.Level]func(args ...interface{}){
			logrus.TraceLevel: logrus.WithContext(ctx).Trace,
			logrus.DebugLevel: logrus.WithContext(ctx).Debug,
			logrus.InfoLevel:  logrus.WithContext(ctx).Info,
			logrus.WarnLevel:  logrus.WithContext(ctx).Warn,
			logrus.ErrorLevel: logrus.WithContext(ctx).Error,
		}
		return lm[lev]
	}
)

// MyFormatter ...
type MyFormatter struct {
	logrus.TextFormatter
	pid string
}

// GetDefaultFormatter returns the default formatter used by all Safescale modules
func GetDefaultFormatter() *MyFormatter {
	return &MyFormatter{
		TextFormatter: logrus.TextFormatter{
			ForceColors:            true,
			TimestampFormat:        "2006-01-02 15:04:05.000",
			FullTimestamp:          true,
			DisableLevelTruncation: true,
		}}
}

// Format ...
func (f *MyFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	if f == nil {
		return nil, fmt.Errorf("invalid instance")
	}

	if f.TextFormatter.DisableLevelTruncation && f.TextFormatter.ForceColors {
		if f.pid == "" {
			f.pid = strconv.Itoa(os.Getpid())
			repeat := pidMaxLength - len(f.pid)
			if repeat > 0 {
				f.pid = strings.Repeat(" ", repeat) + f.pid
			}
		}
		bc, err := f.TextFormatter.Format(entry)
		if err != nil {
			return nil, err
		}

		ticket := string(bc)
		if entry != nil {
			replaced := strings.Replace(ticket, "[20", ""+strings.Repeat(" ", 8-len(entry.Level.String()))+"[20", 1)
			replaced = strings.Replace(replaced, "] ", "]["+entry.Level.String()+"]["+f.pid+"] ", 1)
			if entry.Context != nil {
				theID, ok := entry.Context.Value("ID").(string)
				if ok {
					replaced = strings.Replace(replaced, "] ", "]["+theID+"] ", 1)
				}
			}
			return []byte(replaced), nil
		}

		return []byte(ticket), nil
	}

	return f.TextFormatter.Format(entry)
}

func init() {
	switch runtime.GOOS {
	case "linux":
		data, err := os.ReadFile("/proc/sys/kernel/pid_max")
		if err != nil {
			return
		}
		max := len(strings.TrimSpace(string(data)))
		if max > pidMaxLength {
			pidMaxLength = max
		}
	default:
		pidMaxLength = 5
	}
}
