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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package common

import (
	"expvar"
	"net"
	"net/http"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/global"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/exportstats"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/felixge/fgprof"
	"github.com/mwitkow/go-conntrack"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/zserge/metric"
	"golang.org/x/net/trace"
)

func BuildListener(name, listen string) (net.Listener, error) {
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fail.Wrap(err, "failed listening on %s for '%s'", listen, name)
	}

	out := conntrack.NewListener(listener,
		conntrack.TrackWithName(name),
		conntrack.TrackWithTcpKeepAlive(20*time.Second),
		conntrack.TrackWithTracing(),
	)
	return out, nil
}

// BuildHttpRouter builds the *http.ServeMux to handle requests
func BuildHttpRouter() (*http.ServeMux, fail.Error) {
	mux := http.NewServeMux()

	_ = addMetricsHttpHandler(mux)
	_ = addDebugHttpHandler(mux)

	return mux, nil
}

// addMetricsHttpHandler adds routes serving monitoring purposes (currently Prometheus endpoint)
func addMetricsHttpHandler(mux *http.ServeMux) fail.Error {
	mux.Handle("/metrics", promhttp.Handler())
	return nil
}

// addDebugHttpHandler adds routes serving debugging purposes
func addDebugHttpHandler(mux *http.ServeMux) fail.Error {
	if global.Settings.Debug {
		mux.HandleFunc("/debug/http/requests", func(resp http.ResponseWriter, req *http.Request) {
			trace.Traces(resp, req)
		})
		mux.HandleFunc("/debug/http/events", func(resp http.ResponseWriter, req *http.Request) {
			trace.Events(resp, req)
		})

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
	}

	return nil
}
