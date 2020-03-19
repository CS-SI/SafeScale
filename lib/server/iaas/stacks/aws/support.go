package aws

import (
	"fmt"
	"reflect"
)

// OpContext ...
type OpContext struct {
	ProjectID    string
	DesiredState string
}

// Result ...
type Result struct {
	State string
	Error error
	Done  bool
}

// IPInSubnet ...
type IPInSubnet struct {
	Subnet   string
	Name     string
	ID       string
	IP       string
	PublicIP string
}

func IsOperation(op interface{}, name string, fieldType reflect.Type) bool {
	val := reflect.Indirect(reflect.ValueOf(op))

	result := false

	for i := 0; i < val.Type().NumField(); i++ {

		if val.Type().Field(i).Name == name {
			if val.Type().Field(i).Type == fieldType {
				result = true
				break
			}
		}
	}

	return result
}

func GetOperationStatus(op interface{}, name string, fieldType reflect.Type) (reflect.Value, error) {
	val := reflect.Indirect(reflect.ValueOf(op))

	for i := 0; i < val.Type().NumField(); i++ {

		if val.Type().Field(i).Name == name {
			if val.Type().Field(i).Type == fieldType {
				return reflect.ValueOf(val.Field(i)), nil
			}
		}
	}

	return reflect.Value{}, fmt.Errorf("not found")
}
