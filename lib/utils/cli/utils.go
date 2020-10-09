/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

package cli

// // ExtractRetCode extracts info from the error
// func ExtractRetCode(xerr fail.Error) (string, int, fail.Error) {
// 	retCode := -1
// 	msg := "__ NO MESSAGE __"
// 	if ee, ok := err.(*exec.ExitError); ok {
// 		// Try to get retCode
// 		if status, ok := ee.Sys().(syscall.WaitStatus); ok {
// 			retCode = status.ExitStatus()
// 		} else {
// 			return msg, retCode, fail.InvalidParameterReport("err", "must be a *exec.ExitError and err.Sys() must be a 'syscall.WaitStatus'")
// 		}
// 		// Retrieve error message
// 		msg = ee.Error()
// 		return msg, retCode, nil
// 	}
// 	return msg, retCode, fail.InvalidParameterReport("err", "is not an 'ExitError'")
// }
