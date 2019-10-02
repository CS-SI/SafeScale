/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	baseTimestamp time.Time
	emptyFieldMap logrus.FieldMap

	// LogLevelFnMap is a map between loglevel and log functions from logrus
	LogLevelFnMap = map[logrus.Level]func(args ...interface{}){
		logrus.TraceLevel: logrus.Trace,
		logrus.DebugLevel: logrus.Debug,
		logrus.InfoLevel:  logrus.Info,
		logrus.WarnLevel:  logrus.Warn,
		logrus.ErrorLevel: logrus.Error,
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
	if f.TextFormatter.DisableLevelTruncation && f.TextFormatter.ForceColors {
		if f.pid == "" {
			f.pid = strconv.Itoa(os.Getpid())
			f.pid = strings.Repeat(" ", 5-len(f.pid)) + f.pid
		}
		bc, err := f.TextFormatter.Format(entry)
		ticket := string(bc)
		// replaced := strings.Replace(ticket, "[20", ""+strings.Repeat(" ", 8-len(entry.Level.String()))+"[" + f.pid + "][20", 1)
		replaced := strings.Replace(ticket, "[20", ""+strings.Repeat(" ", 8-len(entry.Level.String()))+"[20", 1)
		replaced = strings.Replace(replaced, "] ", "]["+entry.Level.String()+"]["+f.pid+"] ", 1)

		return []byte(replaced), err
	}

	return f.TextFormatter.Format(entry)
}
