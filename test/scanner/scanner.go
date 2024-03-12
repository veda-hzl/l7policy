package main

import (
	"fmt"
	"os"

	"github.com/flier/gohs/hyperscan"
)

func main() {

	f, err := os.Open("./pattern.i")
	if err != nil {
		fmt.Println("open pattern file failed,", err)
	}
	defer f.Close()

	p, err := hyperscan.ParsePatterns(f)
	if err != nil {
		fmt.Println("parse patterns failed,", err)
	}

	// Create new block database with pattern
	db, err := hyperscan.NewBlockDatabase(p...)
	if err != nil {
		fmt.Println("create database failed,", err)
		return
	}
	defer db.Close()

	// Create new scratch for scanning
	s, err := hyperscan.NewScratch(db)
	if err != nil {
		fmt.Println("create scratch failed,", err)
		return
	}

	defer func() {
		_ = s.Free()
	}()

	// Record matching text
	type Match struct {
		id   uint
		from uint64
		to   uint64
	}

	var matches []Match

	handler := hyperscan.MatchHandler(func(id uint, from, to uint64, flags uint, context interface{}) error {
		matches = append(matches, Match{id, from, to})
		return nil
	})

	data := []byte(`hello xfoobarbar!
	www.baidu.com
	`)

	// Scan data block with handler
	if err := db.Scan(data, s, handler, nil); err != nil {
		fmt.Println("database scan failed,", err)
		return
	}

	// Hyperscan will reports all matches
	for _, m := range matches {
		fmt.Println("match id:", m.id, "[", m.from, ":", m.to, "]", string(data[m.from:m.to]))
	}

}
