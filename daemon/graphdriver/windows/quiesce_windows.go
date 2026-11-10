package windows

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/Microsoft/go-winio/vhd"
	"github.com/containerd/log"
	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

// vmcompute!DeactivateLayer is OpenVirtualDisk + DetachVirtualDisk(flags 0) and nothing else: no volume lock, no
// dismount, no wait, and a failed detach is logged by the platform but reported to us as success. DetachVirtualDisk
// on a mounted volume is a PnP surprise removal of the disk. When a minifilter (for example an antivirus filter that
// still has scans outstanding on the scratch content) holds references on the volume, that removal leaves filter
// instances behind (fltmc shows instances whose volume no longer exists), and the detach has been observed to block
// for good while the caller holds the container lock. See https://github.com/moby/moby/issues/54071.
//
// quiesceVolume does what the platform omits: lock the volume (fails with ERROR_ACCESS_DENIED while any handle is
// open on it, so this is the point where we *wait* for scanners instead of forcing), then dismount it cleanly so the
// filters tear their instances down the regular way, and only then let the caller detach the disk.
//
// Policy on a persistent lock failure is controlled by DOCKER_WINDOWSFILTER_QUIESCE:
//   warn   (default) log and fall back to the platform behaviour (surprise removal), so nothing hangs.
//   strict return an error and leave the layer mounted; the caller reports the failure instead of corrupting the
//          filter stack. A later Put/Remove retries.
//   off    skip quiescing entirely (status quo, for A/B comparison).

const (
	fsctlLockVolume     = 0x00090018
	fsctlDismountVolume = 0x00090020

	quiesceLockTimeout = 60 * time.Second
)

func quiesceMode() string {
	switch m := strings.ToLower(os.Getenv("DOCKER_WINDOWSFILTER_QUIESCE")); m {
	case "strict", "off":
		return m
	default:
		return "warn"
	}
}

// quiesceVolume flushes, locks and dismounts the volume mounted at mountPath (`\\?\Volume{GUID}\`). On success it
// returns a release func that closes the locking handle; the caller keeps the lock held across DeactivateLayer so the
// file system cannot remount the volume between dismount and detach.
func quiesceVolume(ctx context.Context, mountPath string) (release func(), err error) {
	p := strings.TrimSuffix(mountPath, `\`)
	pp, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(pp, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, errors.Wrapf(err, "open volume %s", p)
	}
	defer func() {
		if err != nil {
			windows.CloseHandle(h)
		}
	}()

	var ret uint32
	deadline := time.Now().Add(quiesceLockTimeout)
	delay := 50 * time.Millisecond
	attempts := 0
	for {
		attempts++
		err = windows.DeviceIoControl(h, fsctlLockVolume, nil, 0, nil, 0, &ret, nil)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) || time.Now().After(deadline) {
			return nil, errors.Wrapf(err, "lock volume %s after %d attempts", p, attempts)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
		if delay < 2*time.Second {
			delay *= 2
		}
	}
	if attempts > 1 {
		log.G(ctx).WithField("volume", p).WithField("attempts", attempts).Info("windowsfilter: volume was busy before unmount, waited for it")
	}
	// Flush while locked (lock already forced a flush of dirty data; this makes it explicit), then dismount.
	if err = windows.FlushFileBuffers(h); err != nil {
		return nil, errors.Wrapf(err, "flush volume %s", p)
	}
	if err = windows.DeviceIoControl(h, fsctlDismountVolume, nil, 0, nil, 0, &ret, nil); err != nil {
		return nil, errors.Wrapf(err, "dismount volume %s", p)
	}
	return func() { windows.CloseHandle(h) }, nil
}

// vhdAttached reports whether the VHD at path is still surfaced as a disk. DeactivateLayer swallows DetachVirtualDisk
// failures, so this is the only way to learn whether the detach actually happened.
func vhdAttached(path string) (bool, error) {
	h, err := vhd.OpenVirtualDisk(path, vhd.VirtualDiskAccessNone, vhd.OpenVirtualDiskFlagNone)
	if err != nil {
		return false, errors.Wrapf(err, "open vhd %s", path)
	}
	defer windows.CloseHandle(windows.Handle(h))
	_, err = vhd.GetVirtualDiskPhysicalPath(h)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, windows.ERROR_DEV_NOT_EXIST) || errors.Is(err, windows.ERROR_NOT_READY) {
		return false, nil
	}
	return false, errors.Wrapf(err, "query vhd %s", path)
}
