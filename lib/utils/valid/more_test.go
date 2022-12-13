package valid

import (
	"testing"

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

func Test_hasFieldWithNameAndIsNil(t *testing.T) {

	result, err := hasFieldWithNameAndIsNil(nil, "field")
	require.Nil(t, err)
	require.EqualValues(t, result, false)

	result, err = hasFieldWithNameAndIsNil(struct {
		a string
		b uint
		c bool
	}{}, "")
	require.Contains(t, err.Error(), "CANNOT be empty")

	result, err = hasFieldWithNameAndIsNil(struct {
		a string
		b uint
		c bool
	}{}, "d")
	require.Nil(t, err)
	require.EqualValues(t, result, false)

	result, err = hasFieldWithNameAndIsNil(struct {
		a string
		b uint
		c bool
		d float64
	}{}, "d")
	require.Nil(t, err)
	require.EqualValues(t, result, false)

	result, err = hasFieldWithNameAndIsNil(struct {
		a string
		b uint
		c bool
		d *float64
	}{
		d: nil,
	}, "d")
	require.Nil(t, err)
	require.EqualValues(t, result, true)

}

func Test_IsNil_IsNull(t *testing.T) {
	var aNull Nullable
	var aNil Nillable

	tests := []struct {
		test  interface{}
		isnil bool
	}{
		{test: nil, isnil: true},
		{test: "", isnil: false},
		{test: 42, isnil: false},
		{test: aNull, isnil: false},
		{test: Nullable{isnull: true}, isnil: true},
		{test: &Nullable{isnull: true}, isnil: true},
		{test: Nullable{isnull: false}, isnil: false},
		{test: &Nullable{isnull: false}, isnil: false},
		{test: aNil, isnil: false},
		{test: Nillable{isnil: true}, isnil: true},
		{test: &Nillable{isnil: true}, isnil: true},
		{test: Nillable{isnil: false}, isnil: false},
		{test: &Nillable{isnil: false}, isnil: false},
		{test: "test", isnil: false},
		{test: struct{}{}, isnil: true},
		{test: &struct {
			Price  float64
			Symbol string
			Rating uint
		}{
			Price:  5.55,
			Symbol: "€",
			Rating: 4,
		}, isnil: false},
	}
	for i := range tests {
		require.EqualValues(t, IsNil(tests[i].test), tests[i].isnil)
		require.EqualValues(t, IsNull(tests[i].test), tests[i].isnil)
	}

}
