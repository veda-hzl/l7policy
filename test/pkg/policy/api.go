package policy

import (
	"fmt"
	"l7/pkg/addrobj"
	"l7/pkg/base"
	"l7/pkg/net"
	"l7/pkg/uriobj"
)

var policyCbs PolicyCbs

func init() {
	policyCbs.Init()
}

type PolicyOpPara struct {
	Prio     uint8
	Cidr     string
	Workload base.WorkloadId
	Role     base.WorkRole
	Group    base.WorkGroup
	Dir      base.Direction
	Method   base.Method
	Type     uint8
	Proto    uint8
	Port     uint16
	Httpath  string
}

func PolicyLookup(c *base.Client,
	dir base.Direction,
	method base.Method,
	s *base.ApiService) (*RuleAttr, int) {
	policyCbs.RLock()
	defer policyCbs.RUnlock()

	return policyCbs.Lookup(c, dir, method, s)
}

// cidr format : x.x.x.x/x
func PolicyAdd(arg *PolicyOpPara, action Action) error {

	ip, ml, err := net.ParseCidr(arg.Cidr)
	if err != nil {
		return fmt.Errorf("parse cidr failed,%v", err)
	}

	policyCbs.Lock()
	defer policyCbs.Unlock()

	uri := uriobj.AddUri(arg.Httpath)
	return policyCbs.Update(&RuleCell{
		Prio:     arg.Prio,
		Id:       base.AddrId(addrobj.GetId(ip, ml)),
		Workload: arg.Workload,
		Role:     arg.Role,
		Group:    arg.Group,
		Dir:      arg.Dir,
		Method:   arg.Method,
		Api: base.ApiService{
			Type:  arg.Type,
			Proto: arg.Proto,
			Port:  arg.Port,
			Uri:   base.UriId(uri),
		},
	}, &RuleAttr{
		Action: action,
	})
}

func PolicyDel(arg *PolicyOpPara) error {
	ip, ml, err := net.ParseCidr(arg.Cidr)
	if err != nil {
		return fmt.Errorf("parse cidr failed,%v", err)
	}

	uri := uriobj.FindUri(arg.Httpath)
	if uri == 0 {
		return fmt.Errorf("httpath not found")
	}

	policyCbs.Lock()
	defer policyCbs.Unlock()

	return policyCbs.Delete(&RuleCell{
		Prio:     arg.Prio,
		Id:       base.AddrId(addrobj.GetId(ip, ml)),
		Workload: arg.Workload,
		Role:     arg.Role,
		Group:    arg.Group,
		Dir:      arg.Dir,
		Method:   arg.Method,
		Api: base.ApiService{
			Type:  arg.Type,
			Proto: arg.Proto,
			Port:  arg.Port,
			Uri:   base.UriId(uri),
		},
	})
}

func PolicyDeleteAll() {
	policyCbs.Lock()
	defer policyCbs.Unlock()

	policyCbs.DeleteAll()
}

func ApplyRules() {
	policyCbs.Lock()
	defer policyCbs.Unlock()

	uriobj.Apply()
}

func Len() string {
	return policyCbs.Len()
}

func ApiServiceBuilder(l7type, proto uint8, port uint16, httpath string) ([]base.ApiService, error) {
	var as []base.ApiService

	r, err := uriobj.Scan([]byte(httpath))
	if err != nil {
		return nil, err
	}

	for _, v := range r {
		as = append(as, base.ApiService{
			Type:  l7type,
			Proto: proto,
			Port:  port,
			Uri:   base.UriId(v.Id),
		})
	}

	return as, nil
}
