//go:build !windows

package cli

import "os"

// enableEscapes: a Unix terminal already interprets escape sequences.
func enableEscapes(*os.File) (func(), bool) { return func() {}, true }
