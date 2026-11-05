package upgrade

import (
	"fmt"
	"os"
	"syscall"
)

func recoveryFilePermissions(info os.FileInfo, private, ancestor bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot verify recovery file owner")
	}
	if info.Mode().IsRegular() && stat.Nlink != 1 {
		return fmt.Errorf("recovery file has multiple hard links")
	}
	stickyRootAncestor := ancestor && info.IsDir() && stat.Uid == 0 && info.Mode()&os.ModeSticky != 0
	if (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || (info.Mode().Perm()&0022 != 0 && !stickyRootAncestor) {
		return fmt.Errorf("unsafe recovery path owner or write permissions")
	}
	if private && (stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0) {
		return fmt.Errorf("recovery key must be private to its administrative owner")
	}
	return nil
}
