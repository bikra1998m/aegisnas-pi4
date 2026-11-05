//go:build !linux

package upgrade

import (
	"fmt"
	"os"
	"runtime"
)

func recoveryFilePermissions(info os.FileInfo, private, ancestor bool) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("recovery path permissions are only supported on Linux; Windows is for logic tests")
	}
	// POSIX mode bits do not describe Windows ACLs. The operator must protect
	// the Windows test workspace; production recovery targets Linux.
	return nil
}
