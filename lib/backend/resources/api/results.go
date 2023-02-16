package rscapi

import (
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/result"
)

type StepOutput struct {
	Retcode int
	Output  string
}

type StepResult = result.Holder[StepOutput]

// NewStepResult ...
func NewStepResult(output StepOutput, err error) (StepResult, fail.Error) {
	return result.NewHolder[StepOutput](
		result.WithPayload[StepOutput](output),
		result.TagCompletedFromError[StepOutput](err),
		result.TagSuccessFromCondition[StepOutput](err == nil && output.Retcode == 0),
		result.TagFrozen[StepOutput](),
	)
}

// UnitResults ...
type UnitResults = result.Group[StepOutput, StepResult]

// NewUnitResults ...
func NewUnitResults() UnitResults {
	return result.NewGroup[StepOutput, StepResult]()
}

// Results ...
type Results = result.Group[UnitResults, result.Holder[UnitResults]]

func NewResults() Results {
	return result.NewGroup[UnitResults, result.Holder[UnitResults]]()
}
