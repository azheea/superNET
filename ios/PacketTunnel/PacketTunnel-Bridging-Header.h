// Bridging header of the PacketTunnel extension: the Rust core's C interface,
// plus the kernel-control declarations the extension needs to find its utun
// descriptor (PacketTunnelProvider.tunnelFileDescriptor).
#ifndef PACKET_TUNNEL_BRIDGING_HEADER_H
#define PACKET_TUNNEL_BRIDGING_HEADER_H

#include "../supernet.h"

#include <sys/types.h>
#include <sys/ioctl.h>

// The iOS SDK leaves out <sys/kern_control.h>. Same layout as the macOS SDK's
// (kernel ABI, unchanged since macOS 10.x); WireGuard's iOS app declares them
// the same way.
#if __has_include(<sys/kern_control.h>)
#include <sys/kern_control.h>
#else
#define MAX_KCTL_NAME 96
struct ctl_info {
    u_int32_t ctl_id;
    char ctl_name[MAX_KCTL_NAME];
};
struct sockaddr_ctl {
    u_char sc_len;
    u_char sc_family;
    u_int16_t ss_sysaddr;
    u_int32_t sc_id;
    u_int32_t sc_unit;
    u_int32_t sc_reserved[5];
};
// _IOWR('N', 3, struct ctl_info)
#define CTLIOCGINFO 0xc0644e03UL
#endif

#endif
