package uriobj

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/flier/gohs/hyperscan"
)

const (
	DEFAULT_UOC_SIZE = 65536
	DEFAULT_UOC_FLAG = "i"
	DEFAULT_UOC_URI  = "/"
)

var (
	uoc UriObjCbs
)

func init() {
	uoc.Init(DEFAULT_UOC_FLAG, DEFAULT_UOC_SIZE)
}

type UriObjCbs struct {
	sync.RWMutex
	Um    map[string]uint // uri:id map
	Flags []string
	Rse   *ReSearchEngine //working rse
	Id    uint
}

func (uoc *UriObjCbs) Init(flag string, size uint) {
	var err error

	uoc.Flags = append(uoc.Flags, flag)
	r := strings.NewReader(DEFAULT_UOC_URI)
	p, err := hyperscan.ParsePatterns(r)
	if err != nil {
		panic(err)
	}
	uoc.Rse, err = NewRse(p)
	if err != nil {
		panic(err)
	}

	uoc.Um = make(map[string]uint, size)
}

func (uoc *UriObjCbs) AddUri(uri string) uint {
	uoc.Lock()
	defer uoc.Unlock()

	if v, ok := uoc.Um[uri]; ok {
		return v
	}

	uoc.Id += 1
	v := uoc.Id
	uoc.Um[uri] = v

	return v
}

func (uoc *UriObjCbs) FindUri(uri string) uint {
	uoc.RLock()
	defer uoc.RUnlock()

	if v, ok := uoc.Um[uri]; ok {
		return v
	}

	return 0
}

func (uoc *UriObjCbs) DelUri(uri string) {
	uoc.Lock()
	defer uoc.Unlock()

	delete(uoc.Um, uri)
}

func (uoc *UriObjCbs) DeleteAllUri() {
	uoc.Lock()
	defer uoc.Unlock()

	uoc.Um = make(map[string]uint, 0)
}

func (uoc *UriObjCbs) ReGenerateRse() error {
	var psb, fsb strings.Builder

	for _, v := range uoc.Flags {
		fmt.Fprintf(&fsb, "%s", v)
	}

	for k, v := range uoc.Um {
		fmt.Fprintf(&psb, "%d:/%s/%s\n", v, k, fsb.String())
	}

	r := strings.NewReader(psb.String())
	p, err := hyperscan.ParsePatterns(r)
	if err != nil {
		return err
	}

	n, err := NewRse(p)
	if err != nil {
		return err
	}

	uoc.Lock()
	defer uoc.Unlock()

	uoc.Rse.Destroy()
	uoc.Rse = n

	return nil
}

func (uoc *UriObjCbs) Scan(data []byte) ([]MatchResult, error) {
	return uoc.Rse.Scan(data)
}

func (uoc *UriObjCbs) Len() int {
	return len(uoc.Um)
}

type ReSearchEngine struct {
	magic    uint64 // the rse identity
	patterns hyperscan.Patterns
	db       hyperscan.BlockDatabase
	scratch  *hyperscan.Scratch
}

func (rse *ReSearchEngine) Identity() string {
	return fmt.Sprintf("%d", rse.magic)
}

func (rse *ReSearchEngine) Scan(data []byte) ([]MatchResult, error) {
	matchs := []MatchResult{}
	handler := hyperscan.MatchHandler(func(id uint,
		form, to uint64,
		flags uint,
		context interface{}) error {
		matchs = append(matchs, MatchResult{uint64(id), form, to})

		return nil
	})

	if err := rse.db.Scan(data, rse.scratch, handler, nil); err != nil {
		return nil, err
	}

	return matchs, nil
}

func (rse *ReSearchEngine) Destroy() {
	rse.db.Close()
	rse.scratch.Free()
	rse.patterns = nil
	rse.db = nil
	rse.scratch = nil
}

func NewRse(patterns hyperscan.Patterns) (*ReSearchEngine, error) {
	db, err := hyperscan.NewBlockDatabase(patterns...)
	if err != nil {
		return nil, err
	}

	s, err := hyperscan.NewScratch(db)
	if err != nil {
		db.Close()
		return nil, err
	}

	return &ReSearchEngine{
		magic:    uint64(time.Now().UnixNano()),
		patterns: patterns,
		db:       db,
		scratch:  s,
	}, nil
}

type MatchResult struct {
	Id   uint64
	From uint64
	To   uint64
}

func Apply() {
	uoc.ReGenerateRse()
}

func Scan(data []byte) ([]MatchResult, error) {
	return uoc.Scan(data)
}

func AddUri(uri string) uint {
	return uoc.AddUri(uri)
}

func FindUri(uri string) uint {
	return uoc.FindUri(uri)
}

func DelUri(uri string) {
	uoc.DelUri(uri)
}

func DeleteAllUri() {
	uoc.DeleteAllUri()
}

func Len() int {
	return uoc.Len()
}
