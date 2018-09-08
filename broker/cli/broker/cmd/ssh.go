
		if err != nil {
			if status.Code(err) == codes.DeadlineExceeded {
				return fmt.Errorf("ssh connect took too long to respond")
			}
		}
		return err
	},
}

		_, stdout, stderr, err := client.New().Ssh.Copy(normalizeFileName(c.Args().Get(0)), normalizeFileName(c.Args().Get(1)), 20*time.Second, executionTimeout)
			if status.Code(err) == codes.DeadlineExceeded {
				return fmt.Errorf("ssh copy took too long to respond (may eventually succeed)")
			}
			fmt.Println(stdout)
			fmt.Fprintln(os.Stderr, stderr)
		if err != nil {
			if status.Code(err) == codes.DeadlineExceeded {
				return fmt.Errorf("ssh connect took too long to respond")
			}
		}
		return err
	},
}
