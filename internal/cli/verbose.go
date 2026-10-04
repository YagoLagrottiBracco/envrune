package cli

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/cloud"
)

// traceCloud prints a line to out for every request to EnvRune Cloud: what
// was asked, the answer's status, and how long it took. It is what
// `--verbose` and ENVRUNE_VERBOSE turn on, for finding which request a
// failing command stopped at. Requests carry ciphertext and tokens, so
// neither headers nor bodies are printed.
func traceCloud(out io.Writer) {
	var mu sync.Mutex
	cloud.Trace = func(request string, status int, elapsed time.Duration, err error) {
		mu.Lock()
		defer mu.Unlock()
		answer := "no answer"
		if status != 0 {
			answer = fmt.Sprint(status)
		}
		line := fmt.Sprintf("[cloud] %s: %s in %s", request, answer, elapsed.Round(time.Millisecond))
		if err != nil {
			line += ": " + err.Error()
		}
		fmt.Fprintln(out, line)
	}
}
