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

package tenant

import (
	"fmt"
	"io"
	"os"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/commonlog"
)

func init() {
	logrus.SetFormatter(commonlog.GetDefaultFormatter())
	logrus.SetLevel(logrus.DebugLevel)

	// Log as JSON instead of the default ASCII formatter.
	// logrus.SetFormatter(&logrus.JSONFormatter{})

	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	dirname := utils.AbsPathify("$HOME/.safescale")
	_ = os.MkdirAll(dirname, 0777)

	_, err := os.Stat(dirname)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("Unable to create directory %s", dirname)
		} else {
			fmt.Printf("Directory %s stat error: %v", dirname, err)
		}
		os.Exit(1)
	}

	logFileName := utils.AbsPathify("$HOME/.safescale/safescaled-session.log")
	file, err := os.OpenFile(logFileName, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Printf("Unable to access file %s, make sure the file is writable\n", logFileName)
		os.Exit(1)
	}

	logFileName = utils.AbsPathify("$HOME/.safescale/safescaled-session.log")
	bfile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Printf("Unable to access file %s, make sure the file is writable\n", logFileName)
		os.Exit(1)
	}

	logrus.SetOutput(io.MultiWriter(os.Stdout, file, bfile))
}
