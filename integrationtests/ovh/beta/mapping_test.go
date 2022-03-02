package test

import (
	"fmt"
	"testing"

	"github.com/mitchellh/mapstructure"
)

func Test_Name(t *testing.T) {
	// Note that the mapstructure tags defined in the struct type
	// can indicate which fields the values are mapped to.
	type Person struct {
		Name string `mapstructure:"person_name"`
		Age  int    `mapstructure:"person_age"`
	}

	input := map[string]interface{}{
		"person_age":  91,
		"person_name": "KnowIt",
	}

	var result Person
	err := mapstructure.Decode(input, &result)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("%#v", result)
	// Output:
	// mapstructure.Person{Name:"Mitchell", Age:91}

}
