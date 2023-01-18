package iaas

import (
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"regexp"
	"sort"
	"strings"
)

func searchRegexAdaptor(regex string, templates []*abstract.HostTemplate) []*abstract.HostTemplate {
	var names []string
	byName := make(map[string]*abstract.HostTemplate)
	for _, v := range templates {
		byName[v.Name] = v
	}

	for k, _ := range byName {
		names = append(names, k)
	}

	sre, err := searchRegex(regex, names)
	if err != nil {
		return templates
	}

	var res []*abstract.HostTemplate
	for _, v := range sre {
		res = append(res, byName[v])
	}

	return res
}

func searchRegex(regex string, templates []string) ([]string, error) {
	regexs := strings.Split(regex, "|")
	tmp := make([][]string, len(regexs))

	for i, r := range regexs {
		for _, k := range templates {
			match, err := regexp.MatchString(r, k)
			if err != nil {
				return nil, err
			}

			if match {
				tmp[i] = append(tmp[i], k)
			}
		}
	}

	var res = make([]string, 0, len(templates))

	for i := 0; i < len(tmp); i++ {
		sort.Strings(tmp[i])
		res = append(res, tmp[i]...)
	}

	return res, nil
}
