package iaas

import (
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
		t.FailNow()
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
		t.FailNow()
	}
}

func Test_validateFlexibleengine2(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("lied")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	if err != nil {
		t.Error(err.Error())
		t.FailNow()
	}
}
func Test_validateFlexibleengine(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("flexibleengine")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	if err != nil {
		t.Error(err.Error())
		t.FailNow()
	}
}

func Test_validateGcp(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("gcp")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	if err != nil {
		t.Error(err.Error())
		t.FailNow()
	}
}

func Test_validateOpenstack(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("openstack")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	if err != nil {
		t.Error(err.Error())
		t.FailNow()
	}
}

func Test_inputValidation(t *testing.T) {
	// Having a missing field and a field with the wrong type are aaaaalmost the same, but not quite

	pefo := make(map[string]interface{})
	pefo["name"] = 3 // name is CLEARLY NOT missing, it cannot be more hardcoded than this
	err := validateTenant(pefo)

	if err != nil { // yes, it MUST fail but....
		msg := "Field 'name' for tenant MUST be a string | Missing field 'client' for tenant | No section 'identity' found for tenant | Missing field 'compute' for tenant | missing setting 'AccessKey' field in 'identity' section | missing setting 'ApplicationKey' field in 'identity' section | missing settings 'SecretKey' in 'identity' section | missing setting 'Region' field in 'compute' section"
		require.EqualValues(t, msg, err.Error())
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
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	if err != nil {
		t.Error(err.Error())
		t.FailNow()
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
		t.FailNow()
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
		t.FailNow()
	} else {
		t.Log(err)
	}
}

func Test_validateBadOutscale3(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("wrongoutscale3")

	_, _, xerr := getTenantsFromViperCfg(v)

	require.EqualValues(t, "error reading configuration file: While parsing config: (17, 6): duplicated tables", xerr.Error())
}

func Test_validateBadOutscale4(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("wrongoutscale4")

	tenants, _, xerr := getTenantsFromViperCfg(v)
	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	msg := "missing setting 'UserID' field in 'identity' section | SecretKey in identity section must be alphanumeric and between 1 and 64 characters long | missing setting 'Subregion' field in 'compute' section"
	require.EqualValues(t, msg, err.Error())
}

func Test_validateBadOutscale5(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("wrongoutscale5")

	tenants, _, xerr := getTenantsFromViperCfg(v)
	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	msg := "UserID in identity section must be numeric and between 1 and 64 characters long | SecretKey in identity section must be alphanumeric and between 1 and 64 characters long | Wrong type, the content of tenant[compute][Subregion] is not a string"
	require.EqualValues(t, msg, err.Error())
}

func Test_validateOvh(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("ovh")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	if err != nil {
		t.Error(err.Error())
		t.FailNow()
	}
}

func Test_validateWithoutName(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("name")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
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
		t.FailNow()
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
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	require.EqualValues(t, "failed to find a Provider matching with 'fakeclient'", err.Error())
}

func Test_validateWithoutIdentity(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("identity")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	msg := "No section 'identity' found for tenant Test with tenant without identity section | missing setting 'AccessKey' field in 'identity' section | missing settings 'SecretKey' in 'identity' section"
	require.EqualValues(t, msg, err.Error())
}

func Test_validateWithoutCompute(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("compute")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	msg := "Missing field 'compute' for tenant | missing setting 'Region' field in 'compute' section"
	require.EqualValues(t, msg, err.Error())
}

func Test_validateWithoutUser(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("noUser")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	require.EqualValues(t, "missing setting 'AccessKey' field in 'identity' section", err.Error())
}

func Test_validateGcpWithoutUser(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("noUserGcp")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
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
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	if err != nil {
		t.Error(err.Error())
		t.FailNow()
	}
}

func Test_validateNoAppKey(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("noAppKey")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
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
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	require.EqualValues(t, "missing settings 'SecretKey' in 'identity' section", err.Error())
}

func Test_validateAvailabilityZoneInOStorage(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("availabilityZoneOStorage")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	if err != nil {
		t.Error(err.Error())
		t.FailNow()
	}
}

func Test_validateNoAvailabilityZone(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("noAvailabilityZone")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
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
		t.FailNow()
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
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	require.EqualValues(t, "failed to find a Storage type matching with 'faketype'", err.Error())
}

func Test_validateRegionInMetadata(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("regionMetadata")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	if err != nil {
		t.Error(err.Error())
		t.FailNow()
	}
}

func Test_validateNoRegion(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("noRegion")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	require.EqualValues(t, "missing setting 'Region' field in 'compute' section", err.Error())
}

func Test_wrongTypeForSections(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("wrongSections")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	msg := "Wrong type, the content of tenant[client] is not a string | Wrong type, the content of tenant[identity] is not a map[string]any | Wrong type, the content of tenant[compute] is not a map[string]any | Wrong type, the content of tenant[network] is not a map[string]any | Wrong type, the content of tenant[objectstorage] is not a map[string]any | Wrong type, the content of tenant[metadata] is not a map[string]any | missing setting 'AccessKey' field in 'identity' section | missing setting 'ApplicationKey' field in 'identity' section | missing settings 'SecretKey' in 'identity' section | missing setting 'Region' field in 'compute' section"
	require.EqualValues(t, msg, err.Error())
}

func Test_wrongFieldsType(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("wrongFieldsType")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	msg := "Wrong type, the content of tenant[identity][AccessKey] is not a string | Wrong type, the content of tenant[identity][ApplicationKey] is not a string | Wrong type, the content of tenant[identity][SecretKey] is not a string | Wrong type, the content of tenant[compute][AvailabilityZone] is not a string | Wrong type, the content of tenant[objectstorage][Type] is not a string | Wrong type, the content of tenant[compute][Region] is not a string | Wrong type, the content of tenant[objectstorage][Endpoint] is not a string | Wrong type, the content of tenant[compute][WhitelistTemplateRegexp] is not a string | Wrong type, the content of tenant[metadata][MetadataBucketName] is not a string"
	require.EqualValues(t, msg, err.Error())
}

func Test_invalidFieldsContent(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("invalidFieldsContent")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	msg := "Wrong type, the content of tenant[identity][Username] is not a valid email address | ApplicationKey in identity section must be alphanumeric and between 1 and 64 characters long | AvailabilityZone in compute section must be alphanumeric (with -) and between 1 and 64 characters long | SecretKey in compute section must be alphanumeric (with -) and between 1 and 64 characters long | Endpoint in objectstorage section must be a valid URL | WhitelistTemplateRegexp in compute section must be a valid regex | MetadataBucketName in objectstorage section must be alphanumeric (with -) and between 1 and 255 characters long"
	require.EqualValues(t, msg, err.Error())
}

func Test_invalidFieldsContentOutscale(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("invalidFieldContentOutscale")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	msg := "Wrong type, the content of tenant[identity][UserID] is not a string | Subregion in compute section must be alphanumeric (with -) and between 1 and 64 characters long | Wrong type, the content of tenant[network][VPCName] is not a string | Wrong type, the content of tenant[network][VPCCIDR] is not a string"
	require.EqualValues(t, msg, err.Error())
}

func Test_invalidFieldsContentGcp(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("invalidFieldContentGcp")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	msg := "Wrong type, the content of tenant[identity][User] is not a string"
	require.EqualValues(t, msg, err.Error())
}

func Test_invalidFieldsContentGcp2(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("invalidFieldContentGcp2")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	msg := "User in identity section must be a valid email"
	require.EqualValues(t, msg, err.Error())
}

func Test_unknownFields(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("unknownFields")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	msg := "unknown fields in tenant: map[False:this is wrong] | unknown fields in tenant: map[Unknown:error] | unknown fields in tenant: map[SQLInjection:1 && 1] | unknown fields in tenant: map[Virus:this is a virus]"
	require.EqualValues(t, msg, err.Error())
}

func Test_MaxLifetimeInHours(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("maxLifetimeInHours")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	if err != nil {
		t.Error(err.Error())
		t.FailNow()
	}
}

func Test_BlacklistTemplateRegexp(t *testing.T) {
	v := viper.New()
	v.AddConfigPath("./tenant_tests")
	v.SetConfigName("blacklistTemplateRegexp")

	tenants, _, xerr := getTenantsFromViperCfg(v)

	if xerr != nil {
		t.Error(xerr.Error())
		t.FailNow()
	}

	err := validateTenant(tenants[0])

	if err != nil {
		t.Error(err.Error())
		t.FailNow()
	}
}
