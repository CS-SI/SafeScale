package iaas

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func Test_getTenantsFromCfg(t *testing.T) {
	v := viper.New()
	v.AddConfigPath(".")
	v.SetConfigName("faketenants")

	r, _, xerr := getTenantsFromViperCfg(v)
	if xerr != nil && strings.Contains(xerr.Error(), "Config File \"faketenants\" Not Found") {
		t.Log("Config File \"faketenants\" Not Found")
		t.SkipNow()
		return
	}

	require.Nil(t, xerr)
	theRecoveredTiming := r[0]["timings"].(map[string]interface{})

	s := temporal.MutableTimings{}
	err := mapstructure.Decode(theRecoveredTiming, &s)
	if err != nil {
		t.Error(err.Error())
	}

	require.EqualValues(t, 30*time.Second, s.BigDelay())
}

func Test_validateAws(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("aws")

	tenants, _, _ := getTenantsFromViperCfg(v)

	err := validateTenant(tenants[0])

	if err != nil {
		t.Error(err.Error())
	}
}

func Test_validateCloudferro(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("cloudferro")

	tenants, _, _ := getTenantsFromViperCfg(v)

	err := validateTenant(tenants[0])

	if err != nil {
		t.Error(err.Error())
	}
}

func Test_validateFlexibleengine(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("flexibleengine")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
	}

	err := validateTenant(tenants[0])

	if err != nil {
		t.Error(err.Error())
	}
}

func Test_validateGcp(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("gcp")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		// FIXME: you should add a t.FailNow() here, and also in almost all the other tests after a t.Error, WHY ?
	}

	err := validateTenant(tenants[0]) // FIXME: Because usually when you recover something like a, b, err := whatever(), if you have a err != nil, a and b by convention are null or zero values, so what actually happens is that t.Error (line 94) logs the error, but when we reach line 97, tenants is empty (length 0), so when you try to recover the first element (tenants[0]), it PANICS
	// There is also the possibility of doing 1st a "if len(tenants) > 0" and keep going; it's a choice

	if err != nil {
		t.Error(err.Error())
	}
}

func Test_validateOpenstack(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("openstack")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
	}

	err := validateTenant(tenants[0])

	if err != nil {
		t.Error(err.Error())
	}
}

func Test_inputValidation(t *testing.T) {
	// Having a missing field and a field with the wrong type are aaaaalmost the same, but not quite

	pefo := make(map[string]interface{})
	pefo["name"] = 3 // name is CLEARLY NOT missing, it cannot be more hardcoded than this
	err := validateTenant(pefo)

	if err != nil { // yes, it MUST fail but....
		assert.NotContains(t, err.Error(), "Missing field") // but not like that, the problem is that name is the wrong TYPE, not that is missing
	} else { // no error ??, we have a serious problem then...
		t.FailNow()
	}
}

func Test_validateOutscale(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("outscale")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
	}

	err := validateTenant(tenants[0])

	if err != nil {
		t.Error(err.Error())
	}
}

// Test_validateBadOutscale has to fail, and fail badly at that because there are several mistakes in the tenants.toml file (see the file)
func Test_validateBadOutscale(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("wrongoutscale")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
	}

	err := validateTenant(tenants[0])
	if err == nil {
		t.Error("Ouch!, we didn't saw the errors")
	} else {
		t.Log(err)
	}
}

// Test_validateBadOutscale has to fail, and fail badly at that because there are several mistakes in the tenants.toml file (see the file)
func Test_validateBadOutscale2(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("wrongoutscale2")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
	}

	err := validateTenant(tenants[0])
	if err == nil {
		t.Error("Ouch!, we didn't saw the errors")
	} else {
		t.Log(err)
	}
}

func Test_validateBadOutscale3(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("wrongoutscale3")

	tenants, _, xerr := getTenantsFromViperCfg(v)
	if xerr != nil {
		t.Error(xerr.Error())
		// FIXME: this is missing: (and by the way, is missing in all other tests)
		// t.FailNow()
	}

	// FIXME: do we handle errors properly ?
	// under ANY circumstance our code has to PANIC -> how to fix this ? look at lines 185
	err := validateTenant(tenants[0]) // <- this PANICS
	if err == nil {
		t.Error("Ouch!, we didn't saw the errors")
	} else {
		t.Log(err)
	}
}

func Test_validateOvh(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("ovh")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
	}

	err := validateTenant(tenants[0])

	if err != nil {
		t.Error(err.Error())
	}
}

func Test_validateWithoutName(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("name")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
	}

	err := validateTenant(tenants[0])

	require.EqualValues(t, "Missing field 'name' for tenant", err.Error())
}

func Test_validateWithoutClient(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("client")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
	}

	err := validateTenant(tenants[0])

	require.EqualValues(t, "Missing field 'client' for tenant", err.Error())
}

func Test_validateWithFakeClient(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("fakeclient")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
	}

	err := validateTenant(tenants[0])

	require.EqualValues(t, "Client value be 'aws, cloudferro, ebrc, flexibleengine, gcp, local, openstack, outscale, ovh'", err.Error())
}

func Test_validateWithoutIdentity(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("identity")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
	}

	err := validateTenant(tenants[0])

	require.EqualValues(t, "No section 'identity' found for tenant Test with tenant without identity section", err.Error())
}

func Test_validateWithoutCompute(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("compute")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
	}

	err := validateTenant(tenants[0])

	require.EqualValues(t, "No section 'compute' found for tenant Test with tenant without compute section", err.Error())
}

func Test_validateWithoutUser(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("noUser")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
	}

	err := validateTenant(tenants[0])

	require.EqualValues(t, "missing setting 'AccessKey', 'OpenstackID' or 'Username' field in 'identity' section", err.Error())
}

func Test_validateGcpWithoutUser(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("noUserGcp")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
	}

	err := validateTenant(tenants[0])

	require.EqualValues(t, "missing setting 'User' field in 'identity' section", err.Error())
}

func Test_validateAppKeyInOStorage(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("appKeyOStorage")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
	}

	err := validateTenant(tenants[0])

	if err != nil {
		t.Error(err.Error())
	}
}

func Test_validateNoAppKey(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("noAppKey")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
	}

	err := validateTenant(tenants[0])

	require.EqualValues(t, "missing setting 'ApplicationKey' field in 'identity' section", err.Error())
}

func Test_validateNoSecretKey(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("noSecretKey")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
	}

	err := validateTenant(tenants[0])

	require.EqualValues(t, "missing settings 'SecretKey' or 'AccessPassword' or 'OpenstackPassword' or 'Password' in 'identity' section", err.Error())
}

func Test_validateAvailabilityZoneInOStorage(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("availabilityZoneOStorage")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
	}

	err := validateTenant(tenants[0])

	if err != nil {
		t.Error(err.Error())
	}
}

func Test_validateNoAvailabilityZone(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("noAvailabilityZone")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
	}

	err := validateTenant(tenants[0])

	require.EqualValues(t, "missing settings 'AvailabilityZone' in 'compute' section", err.Error())
}

func Test_validateNoType(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("noType")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
	}

	err := validateTenant(tenants[0])

	require.EqualValues(t, "missing setting 'Type' in 'metadata' or 'objectstorage' section", err.Error())
}

func Test_validateInvalidType(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("invalidType")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
	}

	err := validateTenant(tenants[0])

	require.EqualValues(t, "Type value must be 's3, swift, azure, gce'", err.Error())
}

func Test_validateRegionInMetadata(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("regionMetadata")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
	}

	err := validateTenant(tenants[0])

	if err != nil {
		t.Error(err.Error())
	}
}

func Test_validateNoRegion(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("noRegion")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
	}

	err := validateTenant(tenants[0])

	require.EqualValues(t, "missing setting 'Region' field in 'compute' section", err.Error())
}
