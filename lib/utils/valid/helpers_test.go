package valid_test

import (
	"fmt"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/stretchr/testify/require"
)

type NullableInterface interface {
	IsNull() bool
}
type Nullable struct {
	NullableInterface
	isnull bool
}

func (e Nullable) IsNull() bool {
	return e.isnull
}

type NillableInterface interface {
	IsNil() bool
}
type Nillable struct {
	NillableInterface
	isnil bool
}

func (e Nillable) IsNil() bool {
	return e.isnil
}

func TestIsNull(t *testing.T) {
	var err error
	var ptrerr *error
	var dblptrerr **error
	var nullableNil *Nullable = nil
	var nilableNil *Nillable = nil

	var ourErr fail.Error
	var ptrOurErr *fail.Error
	var dblptrOurErr **fail.Error

	var ourConcreteErr fail.ErrNotFound
	var ptrOurConcreteErr *fail.ErrNotFound
	var dlbPtrOurConcreteErr **fail.ErrNotFound

	// TODO: also test fail.ErrorList{}, being a list we might have surprises

	type args struct {
		something interface{}
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"nil", args{nil}, true},
		{"nil nullable", args{nullableNil}, true},
		{"nil nilable", args{nilableNil}, true},
		{"raw errors 1", args{err}, true},
		{"raw errors 2", args{ptrerr}, true},
		{"raw errors 3", args{dblptrerr}, true},
		{"our errors 1", args{ourErr}, true},
		{"our errors 2", args{ptrOurErr}, true},
		{"our errors 3", args{dblptrOurErr}, true},
		{"our concrete errors 1", args{ourConcreteErr}, true},
		{"our concrete errors 2", args{ptrOurConcreteErr}, true},
		{"our concrete errors 3", args{dlbPtrOurConcreteErr}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := valid.IsNull(tt.args.something); got != tt.want {
				t.Errorf("IsNull() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsNotInitialized(t *testing.T) {
	var err error
	var ptrerr *error
	var dblptrerr **error

	var ourErr fail.Error
	var ptrOurErr *fail.Error
	var dblptrOurErr **fail.Error

	var ourConcreteErr fail.ErrNotFound
	var ptrOurConcreteErr *fail.ErrNotFound
	var dlbPtrOurConcreteErr **fail.ErrNotFound

	// TODO: also test fail.ErrorList{}, being a list we might have surprises

	type args struct {
		something interface{}
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"nil", args{nil}, true},
		{"raw errors 1", args{err}, true},
		{"raw errors 2", args{ptrerr}, true},
		{"raw errors 3", args{dblptrerr}, true},
		{"our errors 1", args{ourErr}, true},
		{"our errors 2", args{ptrOurErr}, true},
		{"our errors 3", args{dblptrOurErr}, true},
		{"our concrete errors 1", args{ourConcreteErr}, true},
		{"our concrete errors 2", args{ptrOurConcreteErr}, true},
		{"our concrete errors 3", args{dlbPtrOurConcreteErr}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := valid.IsNotInitialized(tt.args.something); got != tt.want {
				t.Errorf("IsNull() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNotNulls(t *testing.T) {
	var err = fmt.Errorf("")
	var ptrerr = &err
	var dblptrerr = &ptrerr

	var ourErr = fail.NewError("")
	var ptrOurErr = &ourErr
	var dblptrOurErr = &ptrOurErr

	var ptrOurConcreteErr = fail.NotFoundError("")
	var ourConcreteErr = *ptrOurConcreteErr
	var dlbPtrOurConcreteErr = &ptrOurConcreteErr

	var emptyStrArray []string

	type brand struct {
		content string
	}

	type args struct {
		something interface{}
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"string", args{"whatever"}, false},
		{"array of string", args{[]string{"whatever"}}, false},
		{"array of string empty", args{[]string{}}, false},
		{"array of string empty not initialized", args{emptyStrArray}, false},
		{"struct 1", args{brand{}}, true},                // an empty struct is not nil, it's empty, so -> isnil -> false (it don't works !)
		{"struct 2", args{brand{content: "any"}}, false}, // an empty struct is not nil, it's empty, so -> isnil -> false (it don't works !)
		{"ptr struct", args{&brand{}}, false},
		{"raw errors 1", args{err}, false},
		{"raw errors 2", args{ptrerr}, false},
		{"raw errors 3", args{dblptrerr}, false},
		{"our errors 1", args{ourErr}, false},
		{"our errors 2", args{ptrOurErr}, false},
		{"our errors 3", args{dblptrOurErr}, false},
		{"our concrete errors 1", args{ourConcreteErr}, false},
		{"our concrete errors 2", args{ptrOurConcreteErr}, false},
		{"our concrete errors 3", args{dlbPtrOurConcreteErr}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := valid.IsNull(tt.args.something); got != tt.want {
				t.Errorf("%s: IsNull() = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestInitialized(t *testing.T) {
	var err = fmt.Errorf("")
	var ptrerr = &err
	var dblptrerr = &ptrerr

	var ourErr = fail.NewError("")
	var ptrOurErr = &ourErr
	var dblptrOurErr = &ptrOurErr

	var ptrOurConcreteErr = fail.NotFoundError("")
	var ourConcreteErr = *ptrOurConcreteErr
	var dlbPtrOurConcreteErr = &ptrOurConcreteErr

	var emptyStrArray []string

	type brand struct {
		content string
	}

	type args struct {
		something interface{}
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"string", args{"whatever"}, false},
		{"array of string", args{[]string{"whatever"}}, false},
		{"array of string empty", args{[]string{}}, false},
		{"array of string empty not initialized", args{emptyStrArray}, true},
		{"struct", args{brand{content: "some"}}, false},
		{"struct filled", args{brand{content: "some"}}, false},
		{"ptr struct", args{&brand{}}, false},
		{"ptr struct filled", args{&brand{}}, false},
		{"raw errors 1", args{err}, false},
		{"raw errors 2", args{ptrerr}, false},
		{"raw errors 3", args{dblptrerr}, false},
		{"our errors 1", args{ourErr}, false},
		{"our errors 2", args{ptrOurErr}, false},
		{"our errors 3", args{dblptrOurErr}, false},
		{"our concrete errors 1", args{ourConcreteErr}, false},
		{"our concrete errors 2", args{ptrOurConcreteErr}, false},
		{"our concrete errors 3", args{dlbPtrOurConcreteErr}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := valid.IsNotInitialized(tt.args.something); got != tt.want {
				t.Errorf("%s: IsNull() = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func Test_IsNil(t *testing.T) {

	var aNull Nullable
	var aNil Nillable
	var pNull *Nullable
	var pNil *Nillable

	require.EqualValues(t, valid.IsNil(nil), true)
	require.EqualValues(t, valid.IsNil(aNull), false)
	require.EqualValues(t, valid.IsNil(pNull), true)
	require.EqualValues(t, valid.IsNil(Nullable{isnull: true}), true)
	require.EqualValues(t, valid.IsNil(&Nullable{isnull: true}), true)
	require.EqualValues(t, valid.IsNil(Nullable{isnull: false}), false)
	require.EqualValues(t, valid.IsNil(&Nullable{isnull: false}), false)
	require.EqualValues(t, valid.IsNil(aNil), false)
	require.EqualValues(t, valid.IsNil(pNil), true)
	require.EqualValues(t, valid.IsNil(Nillable{isnil: true}), true)
	require.EqualValues(t, valid.IsNil(&Nillable{isnil: true}), true)
	require.EqualValues(t, valid.IsNil(Nillable{isnil: false}), false)
	require.EqualValues(t, valid.IsNil(&Nillable{isnil: false}), false)
	require.EqualValues(t, valid.IsNil("test"), false)
	require.EqualValues(t, valid.IsNil(&struct {
		Price  float64
		Symbol string
		Rating uint
	}{
		Price:  5.55,
		Symbol: "€",
		Rating: 4,
	}), false)

}
