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

package utils

const (
	BaseFolder  = "/opt/safescale"     // is the path of the base folder containing safescale data on cloud provider instances
	EtcFolder   = BaseFolder + "/etc"  // is the path of the folder containing safescale configurations
	BinFolder   = BaseFolder + "/bin"  // is the path of the folder containing safescale binaries on cloud provider instances
	VarFolder   = BaseFolder + "/var"  // is the path of the folder containing safescale equivalent of /var
	LogFolder   = VarFolder + "/log"   // is the path of the folder containing safescale logs
	TempFolder  = VarFolder + "/tmp"   // is the path of the folder containing safescale temporary files
	StateFolder = VarFolder + "/state" // is the path of the folder containing safescale states
)
