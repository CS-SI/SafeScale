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
	opts := []result.Option[StepOutput]{result.WithPayload[StepOutput](output)}
	if err != nil {
		opts = append(opts, result.MarkAsFailed[StepOutput](err))
	} else {
		opts = append(opts, result.MarkAsCompleted[StepOutput]())
	}
	if output.Retcode == 0 {
		opts = append(opts, result.MarkAsSuccessful[StepOutput]())
	}
	return result.NewHolder[StepOutput](opts...)
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
