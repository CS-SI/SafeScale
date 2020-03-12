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
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	defaultCpuProfileFilename = "safescale_profile_cpu.pprof"
	defaultMemProfileFilename = "safescale_profile_mem.pprof"
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
			filename := constructProfileFilename(content[1], defaultCpuProfileFilename)
			cpufile, err = os.Create(filename)
			if err != nil {
				logrus.Fatalf("Failed to create profile file '%s'", filename)
			}
			_ = pprof.StartCPUProfile(cpufile)
			profileCPU = true
		case "mem", "memory", "ram":
			filename := constructProfileFilename(content[1], defaultMemProfileFilename)
			memfile, err = os.Create(filename)
			if err != nil {
				logrus.Fatalf("could not create memory profile: %v", err)
			}
			profileMemory = true
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
				log.Println(http.ListenAndServe(server, nil))
			}()
		default:
			logrus.Infof("Unsupported profiling option '%s'", v)
		}
	}

	return func() {
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
		path = "./" + defaultCpuProfileFilename
	}
	path = strings.TrimSpace(path)
	st, err := os.Stat(path)
	if err != nil && !os.IsNotExist(err) {
		logrus.Fatalf("Failed to create profile file '%s'", path)
	}
	if st.IsDir() {
		path += "/" + complement
	}
	return path
}
