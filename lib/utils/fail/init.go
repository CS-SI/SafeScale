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
	"runtime"
	"strings"
	"sync/atomic"

	"github.com/sirupsen/logrus"
)

var removePart atomic.Value

func validateInterfaceMatching() {
	{
		val := AbortedReport(nil)
		if _, ok := interface{}(val).(Report); !ok {
			logrus.Fatal("Aborted doesn't satisfy interface Report")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("Aborted doesn't satisfy interface error")
		}
	}

	{
		val := DuplicateReport()
		if _, ok := interface{}(val).(Report); !ok {
			logrus.Fatal("Duplicate doesn't satisfy interface Report")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("Duplicate doesn't satisfy interface error")
		}
	}

	{
		val := ErrorListReport(nil)
		if _, ok := interface{}(val).(Report); !ok {
			logrus.Fatal("ErrorList doesn't satisfy interface Report")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("ErrorList doesn't satisfy interface error")
		}
	}

	{
		val := ForbiddenReport()
		if _, ok := interface{}(val).(Report); !ok {
			logrus.Fatal("Forbidden doesn't satisfy interface Report")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("Forbidden doesn't satisfy interface error")
		}
	}

	{
		val := InconsistentReport()
		if _, ok := interface{}(val).(Report); !ok {
			logrus.Fatal("Inconsistent doesn't satisfy interface Report")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("Inconsistent doesn't satisfy interface error")
		}
	}

	{
		val := InvalidInstanceReport()
		if _, ok := interface{}(val).(Report); !ok {
			logrus.Fatal("InvalidInstance doesn't satisfy interface Report")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("InvalidInstance doesn't satisfy interface error")
		}
	}

	{
		val := InvalidInstanceContentReport("", "")
		if _, ok := interface{}(val).(Report); !ok {
			logrus.Fatal("InvalidInstanceContent doesn't satisfy interface Report")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("InvalidInstanceContent doesn't satisfy interface error")
		}
	}

	{
		val := InvalidParameterReport("", "")
		if _, ok := interface{}(val).(Report); !ok {
			logrus.Fatal("InvalidParameter doesn't satisfy interface Report")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("InvalidParameter doesn't satisfy interface error")
		}
	}

	{
		val := InvalidRequestReport()
		if _, ok := interface{}(val).(Report); !ok {
			logrus.Fatal("InvalidRequest doesn't satisfy interface Report")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("InvalidRequest doesn't satisfy interface error")
		}
	}

	{
		val := NotAuthenticatedReport()
		if _, ok := interface{}(val).(Report); !ok {
			logrus.Fatal("NotAuthenticated doesn't satisfy interface Report")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("NotAuthenticated doesn't satisfy interface error")
		}
	}

	{
		val := NotAvailableReport()
		if _, ok := interface{}(val).(Report); !ok {
			logrus.Fatal("NotAvailable doesn't satisfy interface Report")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("NotAvailable doesn't satisfy interface error")
		}
	}

	{
		val := NotFoundReport("")
		if _, ok := interface{}(val).(Report); !ok {
			logrus.Fatal("NotFound doesn't satisfy interface Report")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("NotFound doesn't satisfy interface error")
		}
	}

	{
		val := NotImplementedReport("")
		if _, ok := interface{}(val).(Report); !ok {
			logrus.Fatal("NotImplemented doesn't satisfy interface Report")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("NotImplemented doesn't satisfy interface error")
		}
	}

	{
		val := OverflowReport(nil, 1)
		if _, ok := interface{}(val).(Report); !ok {
			logrus.Fatal("Overflow doesn't satisfy interface Report")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("Overflow doesn't satisfy interface error")
		}
	}

	{
		val := OverloadReport("")
		if _, ok := interface{}(val).(Report); !ok {
			logrus.Fatal("Overload doesn't satisfy interface Report")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("Overload doesn't satisfy interface error")
		}
	}

	{
		val := RuntimePanicReport("")
		if _, ok := interface{}(val).(Report); !ok {
			logrus.Fatal("RuntimePanic doesn't satisfy interface Report")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("RuntimePanic doesn't satisfy interface error")
		}
	}

	{
		val := SyntaxReport("")
		if _, ok := interface{}(val).(Report); !ok {
			logrus.Fatal("Syntax doesn't satisfy interface Report")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("Syntax doesn't satisfy interface error")
		}
	}

	{
		val := TimeoutReport(nil, 1)
		if _, ok := interface{}(val).(Report); !ok {
			logrus.Fatal("Timeout doesn't satisfy interface Report")
		}
		if _, ok := interface{}(val).(error); !ok {
			logrus.Fatal("Timeout doesn't satisfy interface error")
		}
	}

}

func init() {
	validateInterfaceMatching()

	var rootPath string
	if pc, _, _, ok := runtime.Caller(0); ok {
		if f := runtime.FuncForPC(pc); f != nil {
			rootPath = strings.Split(f.Name(), "lib/utils/")[0]
		}
	}
	removePart.Store(rootPath)
}
