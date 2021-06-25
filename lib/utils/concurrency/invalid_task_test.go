package concurrency

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func generator() Task {
	return &task{}
}

func tgGenerator() TaskGroup {
	return &taskGroup{}
}

func TestInvalidTask(t *testing.T) {
	got := generator()

	err := got.Abort()
	require.NotNil(t, err)

	_, err = got.Abortable()
	require.NotNil(t, err)

	got.Aborted()

	_ = got.DisarmAbortSignal()

	_, err = got.GetID()
	require.NotNil(t, err)

	_ = got.GetSignature()

	_, err = got.GetStatus()
	require.NotNil(t, err)

	_ = got.GetContext()
	require.NotNil(t, err)

	_, err = got.GetLastError()
	require.NotNil(t, err)

	_, err = got.GetResult()
	require.NotNil(t, err)

	err = got.SetID("")
	require.NotNil(t, err)

	_, err = got.Run(nil, nil)
	require.NotNil(t, err)

	_, err = got.Start(nil, nil)
	require.NotNil(t, err)

	_, err = got.StartWithTimeout(nil, nil, 0)
	require.NotNil(t, err)

	_, err = got.Start(nil, nil)
	require.NotNil(t, err)
}

func TestInvalidTaskGroup(t *testing.T) {
	got := tgGenerator()

	err := got.Abort()
	require.NotNil(t, err)

	_, err = got.Abortable()
	require.NotNil(t, err)

	got.Aborted()

	_ = got.DisarmAbortSignal()

	_, err = got.GetID()
	require.NotNil(t, err)

	_ = got.GetSignature()

	_, err = got.GetStatus()
	require.NotNil(t, err)

	_ = got.GetContext()
	require.NotNil(t, err)

	_, err = got.GetLastError()
	require.NotNil(t, err)

	_, err = got.GetResult()
	require.NotNil(t, err)

	err = got.SetID("")
	require.NotNil(t, err)

	_, err = got.Run(nil, nil)
	require.NotNil(t, err)

	_, err = got.Start(nil, nil)
	require.NotNil(t, err)

	_, err = got.StartWithTimeout(nil, nil, 0)
	require.NotNil(t, err)
}
