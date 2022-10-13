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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package externals

import (
	"github.com/CS-SI/SafeScale/v22/lib/backend/externals/consul"
	"github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/factory"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/env"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// Check makes sure configuration is ok
func Check(cmd *cobra.Command) (suffix string, ferr error) {
	logrus.Infoln("Checking configuration")
	_, xerr := factory.GetTenantNames()
	if xerr != nil {
		return "", xerr
	}

	// DEV VAR
	suffix = ""
	// if suffixCandidate := os.Getenv("SAFESCALE_METADATA_SUFFIX"); suffixCandidate != "" {
	suffixCandidate, ok := env.Value("SAFESCALE_METADATA_SUFFIX")
	if ok && suffixCandidate != "" {
		suffix = suffixCandidate
	}
	safescaleEnv, err := env.Keys(env.OptionStartsWithAny("SAFESCALE"))
	if err != nil {
		return "", fail.Wrap(err)
	}

	for _, v := range safescaleEnv {
		value, _ := env.Value(v)
		logrus.Infof("Using %s=%s ", v, value)
	}

	err = terraform.Check()
	if err != nil {
		return "", fail.Wrap(err)
	}

	err = consul.Check()
	if err != nil {
		return "", fail.Wrap(err)
	}

	return suffix, nil
}
