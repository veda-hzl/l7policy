package policy

import (
	"fmt"
	"l7/pkg/addrobj"
	"l7/pkg/base"
	"l7/pkg/uriobj"
	"strings"
	"sync"
)

type PolicyCbs struct {
	sync.RWMutex

	l3 [POLICY_CHAIN_PRIO_OF_MAX]*L3PolicyCbs
	l7 L7PolicyCbs
}

func (p *PolicyCbs) Init() {
	for i := 0; uint8(i) < POLICY_CHAIN_PRIO_OF_MAX; i++ {
		p.l3[i] = new(L3PolicyCbs)
		p.l3[i].Init()
	}
	p.l7.Init()
}

func (p *PolicyCbs) Len() string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "policy-len: l3(")
	for _, v := range p.l3 {
		fmt.Fprintf(&sb, " %d", v.Len())
	}
	fmt.Fprintf(&sb, " ), l7( %d )", p.l7.Len())

	return sb.String()
}

func (p *PolicyCbs) Lookup(c *base.Client,
	dir base.Direction,
	method base.Method,
	s *base.ApiService) (*RuleAttr, int) {
	if c.Workload == 0 && c.Role == 0 {
		return p.l3Match(c, dir, method, s)
	}

	return p.l7Match(c, dir, method, s)
}

func (p *PolicyCbs) Update(rk *RuleCell, ra *RuleAttr) error {
	if rk.Workload == 0 && rk.Role == 0 {
		return p.l3Update(rk.Prio, rk.Id, rk.Dir, rk.Method, &rk.Api, ra)
	}

	return p.l7Update(rk.Workload, rk.Role, rk.Group, rk.Dir, rk.Method, &rk.Api, ra)
}

func (p *PolicyCbs) Delete(rk *RuleCell) error {
	if rk.Workload == 0 && rk.Role == 0 {
		if rk.Prio >= POLICY_CHAIN_PRIO_OF_MAX {
			return fmt.Errorf("too big prio for deleting rule")
		}
		p.l3[rk.Prio].Delete(&L3Key{
			Id:     rk.Id,
			Dir:    rk.Dir,
			Method: rk.Method,
			Api:    rk.Api,
		})
		return nil
	}

	p.l7.Delete(&L7Key{
		Workload: rk.Workload,
		Role:     rk.Role,
		Group:    rk.Group,
		Dir:      rk.Dir,
		Method:   rk.Method,
		Api:      rk.Api,
	})
	return nil
}

func (p *PolicyCbs) DeleteAll() {
	for _, l := range p.l3[:] {
		l.DeleteAll()
	}
	addrobj.DeleteAll()

	p.l7.DeleteAll()
	uriobj.DeleteAllUri()
	uriobj.Apply()
}

func (p *PolicyCbs) l3Match(c *base.Client,
	dir base.Direction,
	method base.Method,
	s *base.ApiService) (*RuleAttr, int) {

	for _, v := range p.l3[:] {
		ids := addrobj.Lookup(c.Ip)
		for _, id := range ids {
			for _, k := range l3KeyEnumerators(&L3Key{
				Id:     base.AddrId(id),
				Dir:    dir,
				Method: method,
				Api: base.ApiService{
					Type:  s.Type,
					Proto: s.Proto,
					Port:  s.Port,
					Uri:   s.Uri,
				},
			}) {
				if r, _ := v.Lookup(&k); r != nil {
					return r, 0
				}
			}
		}
	}

	return nil, 1
}

func l3KeyEnumerators(l3k *L3Key) []L3Key {
	var r []L3Key

	r = append(r, *l3k)

	v := *l3k
	v.Api.Uri = 0
	r = append(r, v)

	v.Api.Uri = l3k.Api.Uri
	v.Method = 0
	r = append(r, v)

	v.Api.Uri = 0
	r = append(r, v)

	return r
}

func (p *PolicyCbs) l7Match(c *base.Client,
	dir base.Direction,
	method base.Method,
	s *base.ApiService) (*RuleAttr, int) {

	for _, v := range l7KeyEnumerators(&L7Key{
		Workload: c.Workload,
		Role:     c.Role,
		Group:    c.Group,
		Dir:      dir,
		Method:   method,
		Api:      *s,
	}) {
		if r, _ := p.l7.Lookup(&v); r != nil {
			return r, 0
		}
	}

	return nil, 1
}

func l7KeyEnumerators(l7k *L7Key) []L7Key {
	var r []L7Key

	r = append(r, *l7k)

	v := *l7k
	r = append(r, v)
	if l7k.Workload != 0 {
		r = appendL7kWorkload(r, l7k, l7k.Workload, l7k.Method, l7k.Api.Uri)
		r = appendL7kWorkload(r, l7k, l7k.Workload, l7k.Method, 0)
		r = appendL7kWorkload(r, l7k, l7k.Workload, 0, l7k.Api.Uri)
		r = appendL7kWorkload(r, l7k, 0, l7k.Method, l7k.Api.Uri)
		r = appendL7kWorkload(r, l7k, l7k.Workload, 0, 0)
		r = appendL7kWorkload(r, l7k, 0, 0, l7k.Api.Uri)
		r = appendL7kWorkload(r, l7k, 0, 0, 0)
	} else if l7k.Role != 0 {
		//////
		r = appendL7kRole(r, l7k, l7k.Role, l7k.Group.App, l7k.Group.Env, l7k.Group.Loc, l7k.Method, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, l7k.Role, l7k.Group.App, l7k.Group.Env, 0, l7k.Method, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, l7k.Role, l7k.Group.App, 0, l7k.Group.Loc, l7k.Method, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, l7k.Role, 0, l7k.Group.Env, l7k.Group.Loc, l7k.Method, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, 0, l7k.Group.App, l7k.Group.Env, l7k.Group.Loc, l7k.Method, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, l7k.Role, l7k.Group.App, 0, 0, l7k.Method, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, l7k.Role, 0, l7k.Group.Env, 0, l7k.Method, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, 0, l7k.Group.App, l7k.Group.Env, 0, l7k.Method, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, l7k.Role, 0, 0, l7k.Group.Loc, l7k.Method, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, 0, l7k.Group.App, 0, l7k.Group.Loc, l7k.Method, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, 0, 0, l7k.Group.Env, l7k.Group.Loc, l7k.Method, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, l7k.Role, 0, 0, 0, l7k.Method, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, 0, l7k.Group.App, 0, 0, l7k.Method, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, 0, 0, l7k.Group.Env, 0, l7k.Method, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, 0, 0, 0, l7k.Group.Loc, l7k.Method, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, 0, 0, 0, 0, l7k.Method, l7k.Api.Uri)

		////
		r = appendL7kRole(r, l7k, l7k.Role, l7k.Group.App, l7k.Group.Env, l7k.Group.Loc, l7k.Method, 0)
		r = appendL7kRole(r, l7k, l7k.Role, l7k.Group.App, l7k.Group.Env, 0, l7k.Method, 0)
		r = appendL7kRole(r, l7k, l7k.Role, l7k.Group.App, 0, l7k.Group.Loc, l7k.Method, 0)
		r = appendL7kRole(r, l7k, l7k.Role, 0, l7k.Group.Env, l7k.Group.Loc, l7k.Method, 0)
		r = appendL7kRole(r, l7k, 0, l7k.Group.App, l7k.Group.Env, l7k.Group.Loc, l7k.Method, 0)
		r = appendL7kRole(r, l7k, l7k.Role, l7k.Group.App, 0, 0, l7k.Method, 0)
		r = appendL7kRole(r, l7k, l7k.Role, 0, l7k.Group.Env, 0, l7k.Method, 0)
		r = appendL7kRole(r, l7k, 0, l7k.Group.App, l7k.Group.Env, 0, l7k.Method, 0)
		r = appendL7kRole(r, l7k, l7k.Role, 0, 0, l7k.Group.Loc, l7k.Method, 0)
		r = appendL7kRole(r, l7k, 0, l7k.Group.App, 0, l7k.Group.Loc, l7k.Method, 0)
		r = appendL7kRole(r, l7k, 0, 0, l7k.Group.Env, l7k.Group.Loc, l7k.Method, 0)
		r = appendL7kRole(r, l7k, l7k.Role, 0, 0, 0, l7k.Method, 0)
		r = appendL7kRole(r, l7k, 0, l7k.Group.App, 0, 0, l7k.Method, 0)
		r = appendL7kRole(r, l7k, 0, 0, l7k.Group.Env, 0, l7k.Method, 0)
		r = appendL7kRole(r, l7k, 0, 0, 0, l7k.Group.Loc, l7k.Method, 0)
		r = appendL7kRole(r, l7k, 0, 0, 0, 0, l7k.Method, 0)

		////
		r = appendL7kRole(r, l7k, l7k.Role, l7k.Group.App, l7k.Group.Env, l7k.Group.Loc, 0, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, l7k.Role, l7k.Group.App, l7k.Group.Env, 0, 0, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, l7k.Role, l7k.Group.App, 0, l7k.Group.Loc, 0, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, l7k.Role, 0, l7k.Group.Env, l7k.Group.Loc, 0, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, 0, l7k.Group.App, l7k.Group.Env, l7k.Group.Loc, 0, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, l7k.Role, l7k.Group.App, 0, 0, 0, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, l7k.Role, 0, l7k.Group.Env, 0, 0, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, 0, l7k.Group.App, l7k.Group.Env, 0, 0, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, l7k.Role, 0, 0, l7k.Group.Loc, 0, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, 0, l7k.Group.App, 0, l7k.Group.Loc, 0, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, 0, 0, l7k.Group.Env, l7k.Group.Loc, 0, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, l7k.Role, 0, 0, 0, 0, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, 0, l7k.Group.App, 0, 0, 0, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, 0, 0, l7k.Group.Env, 0, 0, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, 0, 0, 0, l7k.Group.Loc, 0, l7k.Api.Uri)
		r = appendL7kRole(r, l7k, 0, 0, 0, 0, 0, l7k.Api.Uri)

		////
		r = appendL7kRole(r, l7k, 0, 0, 0, 0, 0, 0)
	}

	return r
}

func appendL7kWorkload(sl []L7Key, l7k *L7Key, workload base.WorkloadId, method base.Method, uri base.UriId) []L7Key {
	var v L7Key

	v.Api, v.Dir = l7k.Api, l7k.Dir
	v.Workload, v.Method, v.Api.Uri = workload, method, uri
	sl = append(sl, v)

	return sl
}

func appendL7kRole(sl []L7Key, l7k *L7Key, role base.WorkRole, app, env, loc uint64, method base.Method, uri base.UriId) []L7Key {

	var v L7Key

	v.Api, v.Dir = l7k.Api, l7k.Dir
	v.Role, v.Method, v.Api.Uri = role, method, uri
	v.Group.App, v.Group.Env, v.Group.Loc = app, env, loc
	sl = append(sl, v)

	return sl
}

func (p *PolicyCbs) l3Update(prio uint8,
	id base.AddrId,
	dir base.Direction,
	method base.Method,
	s *base.ApiService,
	ra *RuleAttr) error {
	if prio >= POLICY_CHAIN_PRIO_OF_MAX {
		return fmt.Errorf("too big policy priority(%d)", prio)
	}

	p.l3[prio].Update(&L3Key{
		Id:     id,
		Dir:    dir,
		Method: method,
		Api:    *s,
	}, ra)

	return nil
}

func (p *PolicyCbs) l7Update(workload base.WorkloadId,
	role base.WorkRole,
	group base.WorkGroup,
	dir base.Direction,
	method base.Method,
	s *base.ApiService,
	ra *RuleAttr) error {

	p.l7.Update(&L7Key{
		Workload: workload,
		Role:     role,
		Group:    group,
		Dir:      dir,
		Method:   method,
		Api:      *s,
	}, ra)

	return nil
}
