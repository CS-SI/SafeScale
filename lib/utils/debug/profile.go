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

package debug

import (
	"context"
	"net/http"
	_ "net/http/pprof" // nolint
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"strconv"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/sirupsen/logrus"
)

const (
	defaultCPUProfileFilenameSuffix   = "_profile_cpu.pprof"
	defaultMemProfileFilenameSuffix   = "_profile_mem.pprof"
	defaultTraceProfileFilenameSuffix = "_profile.trace"
)

// Profile starts profiling based on the content of 'what'
// Must be called with defer: defer debug.Profile("cpu")
func Profile(what string) func() {
	ctx := context.Background()

	if what == "" {
		what = "cpu,mem"
	}

	var (
		profileCPU, profileMemory, profileTrace bool
		cpufile, memfile, tracefile             *os.File
		err                                     error
	)
	parts := strings.Split(what, ",")
	for _, v := range parts {
		content := strings.Split(v, ":")
		switch content[0] {
		case "cpu":
			var filename string
			if len(content) > 1 {
				filename = constructProfileFilename(ctx, content[1], defaultCPUProfileFilenameSuffix)
			} else {
				filename = constructProfileFilename(ctx, "", defaultCPUProfileFilenameSuffix)
			}
			cpufile, err = os.Create(filename)
			if err != nil {
				logrus.WithContext(ctx).Fatalf("Failed to create profile file '%s'", filename)
			}
			_ = pprof.StartCPUProfile(cpufile)
			logrus.WithContext(ctx).Infof("CPU profiling enabled")
			profileCPU = true
		case "mem", "memory", "ram":
			var filename string
			if len(content) > 1 {
				filename = constructProfileFilename(ctx, content[1], defaultMemProfileFilenameSuffix)
			} else {
				filename = constructProfileFilename(ctx, "", defaultMemProfileFilenameSuffix)
			}
			memfile, err = os.Create(filename)
			if err != nil {
				logrus.WithContext(ctx).Fatalf("could not create memory profile: %v", err)
			}
			logrus.WithContext(ctx).Infof("RAM profiling enabled")
			profileMemory = true
		case "trace":
			var filename string
			if len(content) > 1 {
				filename = constructProfileFilename(ctx, content[1], defaultTraceProfileFilenameSuffix)
			} else {
				filename = constructProfileFilename(ctx, "", defaultTraceProfileFilenameSuffix)
			}
			tracefile, err = os.Create(filename)
			if err != nil {
				logrus.WithContext(ctx).Fatalf("Failed to create profile file '%s'", filename)
			}
			_ = trace.Start(tracefile)
			logrus.WithContext(ctx).Infof("Trace profiling enabled")
			profileTrace = true
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
						logrus.WithContext(ctx).Fatalf("invalid port '%s' for web profiler", port)
					}
				}
			}

			runtime.SetBlockProfileRate(1)
			server := listen + ":" + port
			go func() {
				var crash error
				defer fail.SilentOnPanic(&crash)

				err := http.ListenAndServe(server, nil)
				if err != nil {
					logrus.WithContext(ctx).Errorf("ailed to start profiling web ui: %s", err.Error())
				} else {
					logrus.WithContext(ctx).Infof("WEBUI profiling started on %s", server)
				}
			}()
		default:
			logrus.WithContext(ctx).Infof("Unsupported profiling option '%s'", v)
		}
	}

	return func() {
		logrus.WithContext(ctx).Debug("calling debug.Profile() closing func...")
		if profileMemory {
			defer func() {
				_ = memfile.Close()
			}()

			runtime.GC() // get up-to-date statistics
			if err := pprof.WriteHeapProfile(memfile); err != nil {
				logrus.WithContext(ctx).Errorf("could not write memory profile: %v", err)
			}
		}
		if profileCPU {
			pprof.StopCPUProfile()
		}
		if profileTrace {
			trace.Stop()
		}
	}
}

func constructProfileFilename(ctx context.Context, path, complement string) string {
	if path == "" {
		if strings.HasPrefix(os.Args[0], "/") {
			path = os.Args[0] + complement
		} else {
			path = "./" + os.Args[0] + complement
		}
	}
	path = strings.TrimSpace(path)
	st, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			logrus.WithContext(ctx).Fatalf("failed to check if profile file '%s' exists: %s", path, err.Error())
		}
	} else if st.IsDir() {
		path += "/" + os.Args[0] + complement
	}
	return path
}
