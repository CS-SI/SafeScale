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

package iaas

import (
    "fmt"
    "io"
    "os"

    log "github.com/sirupsen/logrus"

    "github.com/CS-SI/SafeScale/lib/utils"
    "github.com/CS-SI/SafeScale/lib/utils/commonlog"
)

func init() {
    log.SetFormatter(commonlog.GetDefaultFormatter())
    log.SetLevel(log.DebugLevel)

    // Log as JSON instead of the default ASCII formatter.
    // log.SetFormatter(&log.JSONFormatter{})

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

    logFileName := utils.AbsPathify("$HOME/.safescale/providers-session.log")
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

    log.SetOutput(io.MultiWriter(os.Stdout, file, bfile))
}
