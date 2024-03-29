package listeners

import (
	"bytes"
	"fmt"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/template"
	"github.com/stretchr/testify/require"
	"regexp"
	"testing"
)

func ExtractFeatureParameters(params []string) (map[string]string, error) {
	re := regexp.MustCompile(`([A-Za-z0-9]+:)?([A-Za-z0-9]+)=([A-Za-z0-9]+)`)
	parsed := make(map[string]string)
	for _, v := range params {
		october := re.FindAllStringSubmatch(v, -1)
		if len(october) > 0 {
			switch len(october[0]) {
			case 3:
				parsed[october[0][1]] = october[0][2]
			case 4:
				parsed[october[0][2]] = october[0][3]
			default:
				continue
			}
		} else {
			return nil, fmt.Errorf("invalid expression: %s", v)
		}
	}

	return parsed, nil
}
func realizeVariables(variables data.Map) (data.Map, fail.Error) {
	cloneV, cerr := data.FromMap(variables)
	if cerr != nil {
		return nil, fail.Wrap(cerr)
	}

	for k, v := range cloneV {
		if variable, ok := v.(string); ok && variable != "" {
			varTemplate, xerr := template.Parse("realize_var", variable)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return cloneV, fail.SyntaxError("error parsing variable '%s': %s", k, xerr.Error())
			}

			buffer := bytes.NewBufferString("")
			err := varTemplate.Option("missingkey=error").Execute(buffer, variables)
			err = debug.InjectPlannedError(err)
			if err != nil {
				return cloneV, fail.ConvertError(err)
			}

			cloneV[k] = buffer.String()
		}
	}

	return cloneV, nil
}

func Test_convertVariablesToDataMap(t *testing.T) {
	var hell []string
	hell = append(hell, "login=wat")
	hell = append(hell, "pass=wot")
	hell = append(hell, "feat:fome={{with .pass}}{{.pass}} {{.puss}}{{end}}")
	hell = append(hell, "feat:lol=wat")
	hell = append(hell, "feat:passz=wot")
	hell = append(hell, "puss=wala")

	dm, _ := ExtractFeatureParameters(hell)
	out, err := convertVariablesToDataMap(dm)
	require.Nil(t, err)
	require.NotNil(t, out)

	dfm, err := realizeVariables(out)
	require.Nil(t, err)
	require.NotNil(t, dfm)
}
