package main

import (
	"fmt"
	"l7/pkg/base"
	"l7/pkg/policy"
	"l7/pkg/uriobj"
	"math/rand"
	"net/netip"
	"time"

	"github.com/Archs/gots/v3/generators"
)

const (
	LOOP         = 1000000
	PATERN_COUNT = 10000
)

var (
	us []string
	ps []policy.PolicyOpPara
)

func main() {
	TestAddPolicyAdd()
	TestPolicyLookup()
	TestDelPolicy()
	TestPolicyLookup()
}

func TestAddPolicyAdd() {

	fmt.Println("Begin to test ADD")
	for i := 0; i < PATERN_COUNT; i++ {
		us = append(us, httpathGenerator(rand.Int63n(9254588373721)))
	}

	for i := 0; i < LOOP; i++ {
		ps = append(ps, policy.PolicyOpPara{
			1,
			"1.2.3.4/16",
			base.WorkloadId(rand.Int63n(1111113121317)),
			1,
			base.WorkGroup{1, 2, 3},
			1,
			1,
			1,
			6,
			80,
			us[rand.Intn(PATERN_COUNT)],
		})
	}

	begin := time.Now()
	for _, v := range ps {
		policy.PolicyAdd(&v, 1)
	}

	d := time.Since(begin)
	fmt.Printf("%s, used time %v, Rate = %d(RPS)\n", policy.Len(), d, uint64(LOOP/d.Seconds()))

	begin = time.Now()
	policy.ApplyRules()
	d = time.Since(begin)

	fmt.Printf("%s, URI paterns: %d, Apply time: %v\n", policy.Len(), uriobj.Len(), d)
	fmt.Println("Test ADD finished.")
}

func TestPolicyLookup() {
	var (
		hit, miss int
	)

	fmt.Println("Begin to test LOOKUP")

	ip, _ := netip.ParseAddr("1.2.3.4")
	begin := time.Now()

	for i := 0; i < LOOP; i++ {

		p := ps[rand.Intn(1000)]
		as, err := policy.ApiServiceBuilder(1, 6, 80, p.Httpath)
		if err != nil {
			fmt.Println("Build ApiService failed,", err)
		}

		for _, v := range as {
			_, err := policy.PolicyLookup(&base.Client{
				Ip:       ip,
				Workload: p.Workload,
				Role:     1,
				Group: base.WorkGroup{
					App: 1,
					Loc: 2,
					Env: 3,
				},
			},
				1,
				1,
				&v)

			if err != 0 {
				miss++
				// fmt.Printf("Lookup-e: %v\n", err)
				continue
			}
			hit++
		}
	}

	d := time.Since(begin)
	fmt.Println(policy.Len(), ", Used time:", d, " Rate:", uint64(LOOP/d.Seconds()), "(RPS)")
	fmt.Println("Test LOOKUP finished, HIT:", hit, "MISS:", miss)
}

func TestDelPolicy() {
	fmt.Println("Begin to test DELETE")
	policy.PolicyDeleteAll()
	fmt.Println("Test DELETEALL finished.")
}

func httpathGenerator(seed int64) string {
	return generators.New(rand.New(rand.NewSource(seed))).URL()
}
