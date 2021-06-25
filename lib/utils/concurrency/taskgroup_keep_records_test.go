package concurrency

import (
	"fmt"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/gophercloud/gophercloud/acceptance/tools"
	"github.com/stretchr/testify/require"
)

// Do we handle the results well ??
func TestKeepRecords(t *testing.T) {
	iter := 0

	for {
		iter++
		if iter > 20 {
			break
		}

		t.Log("Next") // Each time we iterate we see this line, sometimes this doesn't fail at 1st iteration
		overlord, xerr := NewTaskGroup()
		require.NotNil(t, overlord)
		require.Nil(t, xerr)
		xerr = overlord.SetID(fmt.Sprintf("/parent-%d", iter))
		require.Nil(t, xerr)

		for ind := 0; ind < 5; ind++ { // work with 5 tasks
			_, xerr = overlord.Start(
				func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
					mylimit := tools.RandomInt(5, 15)
					for { // iterate only a few times: mylimit
						// some work
						time.Sleep(time.Duration(tools.RandomInt(20, 30)) * time.Millisecond)

						if t.Aborted() || mylimit <= 0 {
							// Cleaning up first before leaving... ;)
							time.Sleep(time.Duration(tools.RandomInt(100, 800)) * time.Millisecond)
							break
						}

						mylimit--
					}

					// flip a coin, true and there is an error, false if it's not
					if tools.RandomInt(0, 2) == 1 {
						return "mistakes happen", fail.NewError("It was head")
					}

					return "who cares", nil
				}, nil, InheritParentIDOption, AmendID(fmt.Sprintf("/child-%d", ind)),
			)
			require.Nil(t, xerr)
		}

		// wait a little until we call wait
		time.Sleep(time.Duration(100) * time.Millisecond)

		res, xerr := overlord.Wait()
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrAborted:
				t.Errorf("Seriously ?, Are we confusing that a group is aborted and that are reported errors in the results ??, nobody is aborting in this test")
				t.FailNow()
			default:
				t.Errorf("Unexpected error: %v", xerr)
				t.FailNow()
			}
		} else {
			require.NotNil(t, res)
			require.NotEmpty(t, res)
		}
	}
}

// Same as before but now with timeouts
func TestKeepRecordsWhenTimeouts(t *testing.T) {
	iter := 0

	for {
		iter++
		if iter > 20 {
			break
		}

		t.Log("Next") // Each time we iterate we see this line, sometimes this doesn't fail at 1st iteration
		overlord, xerr := NewTaskGroup()
		require.NotNil(t, overlord)
		require.Nil(t, xerr)
		xerr = overlord.SetID(fmt.Sprintf("/parent-%d", iter))
		require.Nil(t, xerr)

		for ind := 0; ind < 10; ind++ { // work with 10 tasks
			_, xerr = overlord.Start(
				func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
					mylimit := tools.RandomInt(5, 15)
					for { // iterate only a few times: mylimit
						// some work
						time.Sleep(time.Duration(tools.RandomInt(20, 30)) * time.Millisecond)

						if t.Aborted() || mylimit <= 0 {
							// Cleaning up first before leaving... ;)
							time.Sleep(time.Duration(tools.RandomInt(100, 800)) * time.Millisecond)
							break
						}

						mylimit--
					}

					// flip a coin, true and there is an error, false if it's not
					if tools.RandomInt(0, 2) == 1 {
						return "mistakes happen", fail.NewError("It was head")
					}

					return "who cares", nil
				}, nil, InheritParentIDOption, AmendID(fmt.Sprintf("/child-%d", ind)),
			)
			require.Nil(t, xerr)
		}

		for ind := 0; ind < 10; ind++ { // and 10 unfortunate ones that will likely timeout
			_, xerr = overlord.StartWithTimeout(
				func(t Task, parameters TaskParameters) (TaskResult, fail.Error) {
					mylimit := tools.RandomInt(5, 15)
					for { // iterate only a few times: mylimit
						// some work
						time.Sleep(time.Duration(tools.RandomInt(20, 30)) * time.Millisecond)

						if t.Aborted() || mylimit <= 0 {
							// Cleaning up first before leaving... ;)
							time.Sleep(time.Duration(tools.RandomInt(100, 800)) * time.Millisecond)
							break
						}

						mylimit--
					}

					// flip a coin, true and there is an error, false if it's not
					if tools.RandomInt(0, 2) == 1 {
						return "too late", fail.NewError("It was head")
					}

					return "who cares about timeout", nil
				}, nil, 100*time.Millisecond, InheritParentIDOption, AmendID(fmt.Sprintf("/child-%d", ind)),
			)
			require.Nil(t, xerr)
		}

		// wait a little until we call wait
		time.Sleep(time.Duration(100) * time.Millisecond)

		res, xerr := overlord.Wait()
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrAborted:
				t.Errorf("Seriously ?, Are we confusing that a group is aborted and that are reported errors in the results ??, nobody is aborting in this test")
				t.FailNow()
			default:
				t.Errorf("Unexpected error: %v", xerr)
				t.FailNow()
			}
		} else {
			require.NotNil(t, res)
			require.NotEmpty(t, res)
		}
	}
}
