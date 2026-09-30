//go:build !unix && !windows

package vault

import "os"

func tryLock(*os.File) (bool, error) { return true, nil }
func unlock(*os.File)                {}
