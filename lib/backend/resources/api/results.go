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
		result.TagSuccessFromCondition[StepOutput](output.Retcode == 0),
	)
}

// UnitResults ...
type UnitResults = result.Group[StepResult]

// NewUnitResults ...
func NewUnitResults() UnitResults {
	out := result.NewGroup[StepResult]()
	return any(out).(UnitResults)
}

// Results ...
type Results = result.Group[UnitResults]

func NewResults() Results {
	out := result.NewGroup[UnitResults]()
	return any(out).(Results)
}
