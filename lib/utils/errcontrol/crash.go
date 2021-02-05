package errcontrol

func Crasher(in error, calldepth ...int) (err error) {
	return in
}

func CrashSetup(spec string) error {
	return nil
}