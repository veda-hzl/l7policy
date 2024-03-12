package addrobj

import (
	"encoding/binary"
	"fmt"
	"l7/pkg/base"
	"net/netip"
	"sync"
	"time"
)

var aoc AddrObjCbs

func init() {
	aoc.Init()
}

type Cidr struct {
	Ip      uint32
	MaskLen uint8
}

type AddrObjCbs struct {
	sync.RWMutex
	db map[Cidr]base.AddrId
}

func (a *AddrObjCbs) Init() {
	a.db = make(map[Cidr]base.AddrId, 65536)
}

func (a *AddrObjCbs) Lookup(ip netip.Addr) []base.AddrId {
	var (
		r []base.AddrId
	)

	if !ip.Is4() {
		fmt.Println("Ipv6 is not ready!")
		return r
	}

	u := binary.BigEndian.Uint32(ip.AsSlice())

	a.RLock()
	defer a.RUnlock()

	for i := 32; i >= 0; i-- {
		shift := 32 - i
		k := Cidr{
			Ip:      (u >> shift << shift),
			MaskLen: uint8(i),
		}

		if v, ok := a.db[k]; ok {
			r = append(r, v)
		}
	}

	return r
}

func (a *AddrObjCbs) GetId(ip netip.Addr, masklen uint8) base.AddrId {
	if !ip.Is4() {
		fmt.Println("Ipv6 is not ready!")
		return 0
	}
	u := binary.BigEndian.Uint32(ip.AsSlice())

	a.Lock()
	defer a.Unlock()

	shift := 32 - masklen
	k := Cidr{u >> uint32(shift) << uint32(shift), masklen}
	if r, ok := a.db[k]; ok {
		return r
	}

	r := base.AddrId(time.Now().UnixNano())
	a.db[k] = r

	return r
}

func (a *AddrObjCbs) DelId(ip netip.Addr, masklen uint8) {
	if !ip.Is4() {
		fmt.Println("Ipv6 is not ready!")
	}

	u := binary.BigEndian.Uint32(ip.AsSlice())

	a.Lock()
	defer a.Unlock()

	shift := 32 - masklen
	k := Cidr{u >> uint32(shift) << uint32(shift), masklen}

	delete(a.db, k)
}

func (a *AddrObjCbs) DeleteAll() {
	a.Lock()
	defer a.Unlock()

	for k := range a.db {
		delete(a.db, k)
	}
}

func (a *AddrObjCbs) Len() int {
	return len(a.db)
}

func Lookup(ip netip.Addr) []base.AddrId {
	return aoc.Lookup(ip)
}

func GetId(ip netip.Addr, masklen uint8) base.AddrId {
	return aoc.GetId(ip, masklen)
}

func DelId(ip netip.Addr, masklen uint8) {
	aoc.DelId(ip, masklen)
}

func DeleteAll() {
	aoc.DeleteAll()
}

func Len() int {
	return aoc.Len()
}
