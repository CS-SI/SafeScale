package resources

import (
	"testing"

	"golang.org/x/net/context"
)

func Test_FeatureSliceFromResourceToProtocol(t *testing.T) {
	var rf []*Feature
	flr := FeatureSliceFromResourceToProtocol(context.Background(), rf)
	if len(flr.Features) != 0 {
		t.Error("Invalid FeatureListResponse len")
		t.Fail()
	}
}
