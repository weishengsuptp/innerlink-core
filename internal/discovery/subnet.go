package discovery

import "net"

// ipBroadcast returns the subnet-directed broadcast address for
// the given IPv4 network, or nil if the input is not IPv4 or
// the address is unusable.
//
//   192.168.1.0/24  →  192.168.1.255
//   10.0.0.0/8      →  10.255.255.255
//   172.16.5.0/24   →  172.16.5.255
//
// We don't use net.IP.Broadcast because that would give us the
// "all-ones" broadcast (255.255.255.255) which is treated as
// limited-broadcast by most kernels and doesn't always make it
// past the first hop.
func ipBroadcast(ipnet *net.IPNet) net.IP {
	ip := ipnet.IP.To4()
	if ip == nil {
		return nil
	}
	mask := ipnet.Mask
	if len(mask) != 4 {
		return nil
	}
	bcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		bcast[i] = ip[i] | ^mask[i]
	}
	return bcast
}
