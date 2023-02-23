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
	}

	err := validateTenant(tenants[0])

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
