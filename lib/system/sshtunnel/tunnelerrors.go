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

package sshtunnel

type tunnelError struct {
	error
	isTimeout   bool
	isTemporary bool
}

func (e tunnelError) Unwrap() error {
	return e.error
}

func (e tunnelError) Timeout() bool {
	return e.isTimeout
}

func (e tunnelError) Temporary() bool {
	return e.isTemporary
}

func (e tunnelError) Error() string {
	return e.error.Error()
}
