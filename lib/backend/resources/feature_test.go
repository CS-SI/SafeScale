package resources

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
)

func Test_FeatureSliceFromResourceToProtocol(t *testing.T) {
	var rf []*Feature
	flr, xerr := FeatureSliceFromResourceToProtocol(context.Background(), rf)
	require.Nil(t, xerr)
	if len(flr.Features) != 0 {
		t.Error("Invalid FeatureListResponse len")
		t.Fail()
	}
}
