package net

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

func ParseCidr(cidr string) (netip.Addr, uint8, error) {
	s := strings.Split(cidr, "/")

	if len(s) < 2 {
		return netip.Addr{}, 0, fmt.Errorf("invalid cidr format")
	}

	ip, err := netip.ParseAddr(s[0])
	if err != nil {
		return ip, 0, err
	}

	ml, err := strconv.ParseUint(s[1], 10, 8)
	if err != nil {
		return ip, 0, err
	}

	if ml > 32 {
		return ip, uint8(ml), fmt.Errorf("too big masklen")
	}

	return ip, uint8(ml), nil
}
