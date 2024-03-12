package policy

import (
	"fmt"
	"sync"
	"sync/atomic"
)

type L3PolicyCbs struct {
	sync.RWMutex
	db map[L3Key]*RuleAttr
}

func (p *L3PolicyCbs) Init() {
	p.db = make(map[L3Key]*RuleAttr, 65536)
}

func (p *L3PolicyCbs) Lookup(k *L3Key) (*RuleAttr, error) {
	p.RLock()
	defer p.RUnlock()

	v, ok := p.db[*k]
	if !ok {
		return nil, fmt.Errorf("not found for %v", *k)
	}

	atomic.AddUint64(&v.Counter, 1)
	return &RuleAttr{
		Action:  v.Action,
		Counter: v.Counter,
	}, nil
}

func (p *L3PolicyCbs) Update(k *L3Key, v *RuleAttr) {
	p.Lock()
	defer p.Unlock()

	p.db[*k] = v
}

func (p *L3PolicyCbs) Delete(k *L3Key) {
	p.Lock()
	defer p.Unlock()

	delete(p.db, *k)
}

func (p *L3PolicyCbs) DeleteAll() {
	p.Lock()
	defer p.Unlock()

	for k := range p.db {
		delete(p.db, k)
	}
}

func (p *L3PolicyCbs) Len() int {
	p.RLock()
	defer p.RUnlock()

	return len(p.db)
}
