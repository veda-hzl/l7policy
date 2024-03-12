package policy

import (
	"sync"
	"sync/atomic"
)

type L7PolicyCbs struct {
	sync.RWMutex
	db map[L7Key]*RuleAttr
}

func (p *L7PolicyCbs) Init() {
	p.db = make(map[L7Key]*RuleAttr, 65536)
}

func (p *L7PolicyCbs) Lookup(k *L7Key) (*RuleAttr, int) {
	p.RLock()
	defer p.RUnlock()

	v, ok := p.db[*k]
	if !ok {
		return nil, 1
	}

	atomic.AddUint64(&v.Counter, 1)
	return &RuleAttr{
		Action:  v.Action,
		Counter: v.Counter,
	}, 0
}

func (p *L7PolicyCbs) Update(k *L7Key, v *RuleAttr) {
	p.Lock()
	defer p.Unlock()

	p.db[*k] = v
}

func (p *L7PolicyCbs) Delete(k *L7Key) {
	p.Lock()
	defer p.Unlock()

	delete(p.db, *k)
}

func (p *L7PolicyCbs) DeleteAll() {
	p.Lock()
	defer p.Unlock()

	for k := range p.db {
		delete(p.db, k)
	}
}

func (p *L7PolicyCbs) Len() int {
	p.RLock()
	defer p.RUnlock()

	return len(p.db)
}
