package main

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const appleUTUNCtl = "com.apple.net.utun_control"

/*
 * From ioctl.h:
 * #define	IOCPARM_MASK	0x1fff		// parameter length, at most 13 bits
 * ...
 * #define	IOC_OUT		0x40000000	// copy out parameters
 * #define	IOC_IN		0x80000000	// copy in parameters
 * #define	IOC_INOUT	(IOC_IN|IOC_OUT)
 * ...
 * #define _IOC(inout,group,num,len) \
 * 	(inout | ((len & IOCPARM_MASK) << 16) | ((group) << 8) | (num))
 * ...
 * #define	_IOWR(g,n,t)	_IOC(IOC_INOUT,	(g), (n), sizeof(t))
 *
 * From kern_control.h:
 * #define CTLIOCGINFO     _IOWR('N', 3, struct ctl_info)	// get id from name
 *
 */

const appleCTLIOCGINFO = (0x40000000 | 0x80000000) | ((100 & 0x1fff) << 16) | uint32(byte('N'))<<8 | 3

/*
 * #define _IOW(g,n,t) _IOC(IOC_IN, (g), (n), sizeof(t))
 * #define TUNSIFMODE _IOW('t', 94, int)
 */
const appleTUNSIFMODE = (0x80000000) | ((4 & 0x1fff) << 16) | uint32(byte('t'))<<8 | 94

/*
 * struct sockaddr_ctl {
 *     u_char sc_len; // depends on size of bundle ID string
 *     u_char sc_family; // AF_SYSTEM
 *     u_int16_t ss_sysaddr; // AF_SYS_KERNCONTROL
 *     u_int32_t sc_id; // Controller unique identifier
 *     u_int32_t sc_unit; // Developer private unit number
 *     u_int32_t sc_reserved[5];
 * };
 */
type sockaddrCtl struct {
	scLen      uint8
	scFamily   uint8
	ssSysaddr  uint16
	scID       uint32
	scUnit     uint32
	scReserved [5]uint32
}

var sockaddrCtlSize uintptr = 32

// openDevSystem opens tun device on system
func openDevSystem(deviceName string) (file *os.File, err error) {

	ifIndex := -1
	if deviceName != "" {
		const utunPrefix = "utun"
		if !strings.HasPrefix(deviceName, utunPrefix) {
			return nil, fmt.Errorf("Interface name must be utun[0-9]+")
		}
		ifIndex, err = strconv.Atoi(deviceName[len(utunPrefix):])
		if err != nil || ifIndex < 0 || ifIndex > math.MaxUint32-1 {
			return nil, fmt.Errorf("Interface name must be utun[0-9]+")
		}
	}

	var fd int
	// Supposed to be socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL), but ...
	//
	// In sys/socket.h:
	// #define PF_SYSTEM	AF_SYSTEM
	//
	// In sys/sys_domain.h:
	// #define SYSPROTO_CONTROL       	2	/* kernel control protocol */
	if fd, err = syscall.Socket(syscall.AF_SYSTEM, syscall.SOCK_DGRAM, 2); err != nil {
		return nil, fmt.Errorf("error in syscall.Socket: %v", err)
	}

	var ctlInfo = &struct {
		ctlID   uint32
		ctlName [96]byte
	}{}
	copy(ctlInfo.ctlName[:], []byte(appleUTUNCtl))

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(appleCTLIOCGINFO), uintptr(unsafe.Pointer(ctlInfo))); errno != 0 {
		err = errno
		return nil, fmt.Errorf("error in syscall.Syscall(syscall.SYS_IOCTL, ...): %v", err)
	}

	addrP := unsafe.Pointer(&sockaddrCtl{
		scLen:    uint8(sockaddrCtlSize),
		scFamily: syscall.AF_SYSTEM,

		/* #define AF_SYS_CONTROL 2 */
		ssSysaddr: 2,

		scID:   ctlInfo.ctlID,
		scUnit: uint32(ifIndex) + 1,
	})
	if _, _, errno := syscall.RawSyscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(addrP), uintptr(sockaddrCtlSize)); errno != 0 {
		err := errno
		return nil, fmt.Errorf("error in syscall.RawSyscall(syscall.SYS_CONNECT, ...): %v", err)
	}

	var ifName struct {
		name [16]byte
	}
	ifNameSize := uintptr(16)
	if _, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd),
		2, /* #define SYSPROTO_CONTROL 2 */
		2, /* #define UTUN_OPT_IFNAME 2 */
		uintptr(unsafe.Pointer(&ifName)),
		uintptr(unsafe.Pointer(&ifNameSize)), 0); errno != 0 {
		err = errno
		return nil, fmt.Errorf("error in syscall.Syscall6(syscall.SYS_GETSOCKOPT, ...): %v", err)
	}

	if err = syscall.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("setting non-blocking error")
	}

	return os.NewFile(uintptr(fd), string(ifName.name[:])), nil
}
