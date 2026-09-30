// Probe is the child process of the CLI integration tests. It runs the same
// way on every platform and executes its arguments as steps:
//
//	print NAME     prints NAME=value from its environment
//	pwd            prints its working directory
//	sleep 2s       waits
//	exit N         exits with code N
//	heartbeat F    starts a grandchild that writes to file F every 100ms
//	tty            prints tty=true when its output is a terminal
//	read           reads a line and prints got LINE
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

func main() {
	args := os.Args[1:]
	for len(args) > 0 {
		step := args[0]
		switch step {
		case "pwd":
			wd, _ := os.Getwd()
			fmt.Println("pwd=" + wd)
			args = args[1:]
			continue
		case "tty":
			fmt.Printf("tty=%t\n", term.IsTerminal(int(os.Stdout.Fd())))
			args = args[1:]
			continue
		case "read":
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			fmt.Println("got " + strings.TrimSpace(line))
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
