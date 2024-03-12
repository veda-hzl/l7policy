package base

import "net/netip"

const (
	SERVICE_OF_HTTP uint8 = 1 + iota
)

const (
	HTTP_GET = 1 + iota
	HTTP_HEAD
	HTTP_POST
	HTTP_PUT
	HTTP_DELETE
	HTTP_CONNECT
	HTTP_OPTIONS
	HTTP_TRACE
	HTTP_PATCH
)

const (
	L7_ANY = iota
	L7_INGRESS
	L7_EGRESS
)

type AddrId uint64
type WorkloadId uint64
type WorkRole uint64
type Method uint8
type Direction uint8

type URI string
type UriId uint

type WorkGroup struct {
	App uint64
	Loc uint64
	Env uint64
}

type ApiService struct {
	Type  uint8  // http ...
	Proto uint8  // tcp、udp ...
	Port  uint16 // port number
	Uri   UriId  // api id
}

type Client struct {
	Ip       netip.Addr
	Workload WorkloadId
	Role     WorkRole
	Group    WorkGroup
}
