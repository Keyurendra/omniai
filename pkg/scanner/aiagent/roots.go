package aiagent

import (
	"os"
	"path/filepath"
)

func DiscoverRoots(mountpoint string, osType string) []string {
	switch osType {
	case "linux":
		return discoverLinuxRoots(mountpoint)
	case "windows":
		return discoverWindowsRoots(mountpoint)
	case "macos":
		return discoverMacOSRoots(mountpoint)
	default:
		return []string{mountpoint}
	}
}	

func discoverLinuxRoots(mountpoint string) []string {
	candidates := []string{
		filepath.Join(mountpoint, "usr/bin"),
		filepath.Join(mountpoint, "usr/local/bin"),
		filepath.Join(mountpoint, "usr/lib"),
		filepath.Join(mountpoint, "usr/local/lib"),
		filepath.Join(mountpoint, "opt"),
		filepath.Join(mountpoint, "root"),
		filepath.Join(mountpoint, "home"),
	}

	var roots []string

	for _, root := range candidates {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			roots = append(roots, root)
		}
	}

	return roots
}

func discoverWindowsRoots(mountpoint string) []string {
	if info, err := os.Stat(mountpoint); err == nil && info.IsDir() {
		return []string{mountpoint}
	}

	return nil
}

func discoverMacOSRoots(mountpoint string) []string {
	if info, err := os.Stat(mountpoint); err == nil && info.IsDir() {
		return []string{mountpoint}
	}

	return nil
}
