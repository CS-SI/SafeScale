package operations

import (
	"context"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/sirupsen/logrus"
)

func tak(inctx context.Context, params interface{}) (_ interface{}, _ fail.Error) {
	time.Sleep(50 * time.Millisecond)
	return "amazing", nil
}

func taf(inctx context.Context, params interface{}) (_ interface{}, _ fail.Error) {
	time.Sleep(50 * time.Millisecond)
	logrus.Info("One more round")
	return nil, fail.NewError("it failed")
}

func tap(inctx context.Context, params interface{}) (_ interface{}, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	time.Sleep(50 * time.Millisecond)
	logrus.Info("One more round")
	panic("boom")
}

func TestRunWindow(t *testing.T) {
	type args struct {
		inctx      context.Context
		count      uint
		windowSize uint
		uat        chan StdResult
		runner     func(context.Context, interface{}) (interface{}, fail.Error)
		data       interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "basic",
			args: args{
				inctx:      context.Background(),
				count:      4,
				windowSize: 2,
				uat:        make(chan StdResult, 200),
				runner:     tak,
				data:       struct{}{},
			},
			wantErr: false,
		},
		{
			name: "error",
			args: args{
				inctx:      context.Background(),
				count:      3,
				windowSize: 2,
				uat:        make(chan StdResult),
				runner:     tak,
				data:       struct{}{},
			},
			wantErr: true,
		},
		{
			name: "basic with error",
			args: args{
				inctx:      context.Background(),
				count:      4,
				windowSize: 1,
				uat:        make(chan StdResult, 200),
				runner:     taf,
				data:       struct{}{},
			},
			wantErr: true,
		},
		{
			name: "basic with panic",
			args: args{
				inctx:      context.Background(),
				count:      4,
				windowSize: 1,
				uat:        make(chan StdResult, 200),
				runner:     tap,
				data:       struct{}{},
			},
			wantErr: true,
		},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ttctx, cancel := context.WithCancel(tt.args.inctx)
			time.AfterFunc(5*time.Second, cancel)
			if err := runWindow(ttctx, tt.args.count, tt.args.windowSize, tt.args.uat, tt.args.runner, tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("RunWindow() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRunWindow2(t *testing.T) {
	type args struct {
		inctx      context.Context
		count      uint
		windowSize uint
		uat        chan StdResult
		runner     func(context.Context, interface{}) (interface{}, fail.Error)
		data       interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "basic",
			args: args{
				inctx:      context.Background(),
				count:      3,
				windowSize: 2,
				uat:        make(chan StdResult, 5),
				runner:     tak,
				data:       struct{}{},
			},
			wantErr: false,
		},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ttctx, cancel := context.WithCancel(tt.args.inctx)
			time.AfterFunc(7*time.Second, cancel)
			if err := runWindow(ttctx, tt.args.count, tt.args.windowSize, tt.args.uat, tt.args.runner, tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("RunWindow() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
