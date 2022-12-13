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
	v.SetConfigName("faketenant")

	r, _, xerr := getTenantsFromViperCfg(v)
	if xerr != nil && strings.Contains(xerr.Error(), "Config File \"faketenant\" Not Found") {
		t.Log("Config File \"faketenant\" Not Found")
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
