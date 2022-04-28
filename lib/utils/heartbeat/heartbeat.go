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

package heartbeat

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

const notAvailableMessage = "Not available"

var commitHash string
var startTime time.Time

type heartbeatMessage struct {
	Status string `json:"status"`
	Build  string `json:"build"`
	Uptime string `json:"uptime"`
}

func init() {
	startTime = time.Now()
}

func handler(rw http.ResponseWriter, _ *http.Request) {
	hash := commitHash
	if hash == "" {
		hash = notAvailableMessage
	}
	uptime := time.Since(startTime).String()
	err := json.NewEncoder(rw).Encode(heartbeatMessage{"running", hash, uptime})
	if err != nil {
		logrus.Errorf("Failed to write heartbeat message. Reason: %s", err.Error())
		_ = json.NewEncoder(rw).Encode(heartbeatMessage{})
	}
}

func RunHeartbeatService(address string) {
	http.HandleFunc("/heartbeat", handler)
	logrus.Println(http.ListenAndServe(address, nil))
}
