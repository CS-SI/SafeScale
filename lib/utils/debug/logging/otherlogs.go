/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

package logging

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/sirupsen/logrus"
)

var otherLog *logrus.Logger

func NewTunnelLogger() {
	otherLog = logrus.New()
	otherLog.SetFormatter(&logrus.JSONFormatter{})
	otherLog.SetLevel(logrus.DebugLevel)

	dirname := utils.AbsPathify("$HOME/.safescale")
	_ = os.MkdirAll(dirname, 0777)

	_, err := os.Stat(dirname)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("Unable to create directory %s\n", dirname)
		} else {
			fmt.Printf("Directory %s stat error: %v\n", dirname, err)
		}
		os.Exit(1)
	}

	logFileName := utils.AbsPathify("$HOME/.safescale/safescaled-tunnels.log")
	file, err := os.OpenFile(logFileName, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Printf("Unable to access file %s, make sure the file is writable\n", logFileName)
		os.Exit(1)
	}

	if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
		if strings.Contains(forensics, "tunnel") {
			otherLog.SetOutput(io.MultiWriter(os.Stdout, file))
		} else {
			otherLog.SetOutput(file)
		}
	} else {
		otherLog.SetOutput(file)
	}
}

func GetTunnelLogger() *logrus.Logger {
	return otherLog
}
