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

package debug

import (
    "net/http"
    _ "net/http/pprof" // nolint
    "os"
    "runtime"
    "runtime/pprof"
    "strconv"
    "strings"

    "github.com/sirupsen/logrus"
)

const (
    defaultCPUProfileFilenameSuffix = "_profile_cpu.pprof"
    defaultMemProfileFilenameSuffix = "_profile_mem.pprof"
)

// Profile starts profiling based on the content of 'what'
// Must be called with defer: defer debug.Profile("cpu")
func Profile(what string) func() {
    if what == "" {
        what = "cpu,mem"
    }

    var (
        profileCPU, profileMemory bool
        cpufile, memfile          *os.File
        err                       error
    )
    parts := strings.Split(what, ",")
    for _, v := range parts {
        content := strings.Split(v, ":")
        switch content[0] {
        case "cpu":
            var filename string
            if len(content) > 1 {
                filename = constructProfileFilename(content[1], defaultCPUProfileFilenameSuffix)
            } else {
                filename = constructProfileFilename("", defaultCPUProfileFilenameSuffix)
            }
            cpufile, err = os.Create(filename)
            if err != nil {
                logrus.Fatalf("Failed to create profile file '%s'", filename)
            }
            _ = pprof.StartCPUProfile(cpufile)
            profileCPU = true
            logrus.Infof("CPU profiling enabled")
        case "mem", "memory", "ram":
            var filename string
            if len(content) > 1 {
                filename = constructProfileFilename(content[1], defaultMemProfileFilenameSuffix)
            } else {
                filename = constructProfileFilename("", defaultMemProfileFilenameSuffix)
            }
            memfile, err = os.Create(filename)
            if err != nil {
                logrus.Fatalf("could not create memory profile: %v", err)
            }
            profileMemory = true
            logrus.Infof("RAM profiling enabled ")
        case "web", "www":
            listen := "localhost"
            port := "6060"
            contentLen := len(content)
            if contentLen > 1 {
                listen = content[1]
                if contentLen > 2 {
                    port = content[2]
                    _, err = strconv.Atoi(port)
                    if err != nil {
                        logrus.Fatalf("invalid port '%s' for web profiler", port)
                    }
                }
            }

            runtime.SetBlockProfileRate(1)
            server := listen + ":" + port
            go func() {
                err := http.ListenAndServe(server, nil)
                if err != nil {
                    logrus.Errorf("Failed to start profiling web ui: %s", err.Error())
                } else {
                    logrus.Infof("WEBUI profiling started on %s", server)
                }
            }()
        default:
            logrus.Infof("Unsupported profiling option '%s'", v)
        }
    }

    return func() {
        logrus.Debugf("calling debug.Profile() closing func...")
        if profileMemory {
            defer func() {
                _ = memfile.Close()
            }()

            runtime.GC() // get up-to-date statistics
            if err := pprof.WriteHeapProfile(memfile); err != nil {
                logrus.Errorf("could not write memory profile: %v", err)
            }
        }
        if profileCPU {
            pprof.StopCPUProfile()
        }
    }
}

func constructProfileFilename(path, complement string) string {
    if path == "" {
        path = "./" + os.Args[0] + complement
    }
    path = strings.TrimSpace(path)
    st, err := os.Stat(path)
    if err != nil {
        if !os.IsNotExist(err) {
            logrus.Fatalf("failed to check if profile file '%s' exists: %s", path, err.Error())
        }
    } else if st.IsDir() {
        path += "/" + os.Args[0] + complement
    }
    return path
}
