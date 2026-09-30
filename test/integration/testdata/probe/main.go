// Probe is the child process of the CLI integration tests. It runs the same
// way on every platform and executes its arguments as steps:
//
//	print NAME     prints NAME=value from its environment
//	pwd            prints its working directory
//	sleep 2s       waits
//	exit N         exits with code N
//	heartbeat F    starts a grandchild that writes to file F every 100ms
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"
)

func main() {
	args := os.Args[1:]
	for len(args) > 0 {
		step := args[0]
		if step == "pwd" {
			wd, _ := os.Getwd()
			fmt.Println("pwd=" + wd)
			args = args[1:]
			continue
		}
		if len(args) < 2 {
			fail("step %s needs an argument", step)
		}
		arg := args[1]
		args = args[2:]
		switch step {
		case "print":
			fmt.Printf("%s=%s\n", arg, os.Getenv(arg))
		case "sleep":
			d, err := time.ParseDuration(arg)
			if err != nil {
				fail("bad duration %q", arg)
			}
			time.Sleep(d)
		case "exit":
			code, err := strconv.Atoi(arg)
			if err != nil {
				fail("bad exit code %q", arg)
			}
			os.Exit(code)
		case "heartbeat":
			if err := exec.Command(os.Args[0], "beat", arg).Start(); err != nil {
				fail("heartbeat: %v", err)
			}
		case "beat":
			for {
				_ = os.WriteFile(arg, []byte(time.Now().String()), 0600)
				time.Sleep(100 * time.Millisecond)
			}
		default:
			fail("unknown step %q", step)
		}
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "probe: "+format+"\n", args...)
	os.Exit(2)
}
