//go:build debug
// +build debug

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

package common

import (
	"expvar"
	"net/http"

	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/exportstats"
	"github.com/felixge/fgprof"
	"github.com/sirupsen/logrus"
	"github.com/zserge/metric"
)

func ExposeRuntimeMetrics(mux *http.ServeMux) {
	logrus.Debugf("Exposing debug server")
	defer func() {
		logrus.Debugf("Exposed debug server")
	}()

	// // DEV VAR
	// expvarPort := 9191
	// if port := os.Getenv("SAFESCALE_EXPVAR_PORT"); port != "" {
	// 	num, err := strconv.Atoi(port)
	// 	if err != nil {
	// 		expvarPort = num
	// 	}
	// }

	// Track using expvar
	expvar.NewInt("tenant.set")
	expvar.NewInt("maybes")
	expvar.NewInt("metadata.reads")
	expvar.NewInt("metadata.writes")
	expvar.NewInt("metadata.cache.hits")
	expvar.NewInt("host.cache.hit")
	expvar.NewInt("net.cache.hit")
	expvar.NewInt("cluster.cache.hit")
	expvar.NewInt("newhost.cache.hit")
	expvar.NewInt("newhost.cache.read")

	exportstats.NewStatCount("stats")
	mux.Handle("/debug/metrics", metric.Handler(metric.Exposed))

	// Debug using fgprof
	mux.Handle("/debug/fgprof", fgprof.Handler())

	// go func() {
	// 	var crash error
	// 	defer fail.SilentOnPanic(&crash)
	//
	// 	err := http.ListenAndServe(fmt.Sprintf(":%d", expvarPort), http.DefaultServeMux)
	// 	if err != nil {
	// 		logrus.Fatalf("Failed to start expvar: %v", err)
	// 	}
	// }()
}
