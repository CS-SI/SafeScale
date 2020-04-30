/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package fail

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/CS-SI/SafeScale/lib/utils/commonlog"
)

const (
	// errorOccurred       = "ERROR OCCURRED"
	// outputErrorTemplate = "%s " + errorOccurred + ": %+v"
	outputErrorTemplate = "%s: %+v"
)

// OnExitLogErrorWithLevel returns a function that will log error with the log level wanted
func OnExitLogErrorWithLevel(in string, err *error, level logrus.Level) {
	logLevelFn, ok := commonlog.LogLevelFnMap[level]
	if !ok {
		logLevelFn = logrus.Error
	}

	if IsGRPCError(*err) {
		if err != nil && *err != nil {
			logLevelFn(fmt.Sprintf(outputErrorTemplate, in, grpcstatus.Convert(*err).Message()))
		}
		return
	}

	if len(in) == 0 {
		in = extractCallerName()
	}

	if err != nil && *err != nil {
		logLevelFn(fmt.Sprintf(outputErrorTemplate, in, *err))
	}
}

func extractCallerName() string {
	// if 'in' is empty, recover function name from caller
	var out string
	toSkip := 0
	for {
		if pc, _, line, ok := runtime.Caller(toSkip); ok {
			if f := runtime.FuncForPC(pc); f != nil {
				if strings.Contains(f.Name(), "fail.OnExitLog") || strings.Contains(f.Name(), "fail.extractCallerName") {
					toSkip++
					continue
				}
				out = filepath.Base(f.Name() + fmt.Sprintf(",%d", line))
				break
			}
		}

		if toSkip >= 6 { // Unlikely to reach this point
			break
		}
	}
	return out
}

// OnExitLogError logs error with level logrus.ErrorLevel.
func OnExitLogError(in string, err *error) {
	OnExitLogErrorWithLevel(in, err, logrus.ErrorLevel)
}

// OnExitTraceError logs error with level logrus.TraceLevel.
func OnExitTraceError(in string, err *error) {
	OnExitLogErrorWithLevel(in, err, logrus.TraceLevel)
}

// OnExitLogReportWithLevel logs report with the log level wanted
func OnExitLogReportWithLevel(in string, err *Report, level logrus.Level) {
	logLevelFn, ok := commonlog.LogLevelFnMap[level]
	if !ok {
		logLevelFn = logrus.Error
	}

	if len(in) == 0 {
		in = extractCallerName()
	}

	if err != nil && *err != nil {
		logLevelFn(fmt.Sprintf(outputErrorTemplate, in, *err))
	}
}

// OnExitLogReport logs report with level logrus.ErrorLevel
func OnExitLogReport(in string, err *Report) {
	OnExitLogReportWithLevel(in, err, logrus.ErrorLevel)
}

// OnExitTraceReport logs report with level logrus.TraceLevel
func OnExitTraceReport(in string, err *Report) {
	OnExitLogReportWithLevel(in, err, logrus.TraceLevel)
}

// OnPanic captures panic error and fill the error pointer with a RuntimePanic.
func OnPanic(err *error) {
	if x := recover(); x != nil {
		*err = *RuntimePanicReport("runtime panic occurred: %+v", x)
	}
}
