package policy

import "l7/pkg/base"

const (
	POLICY_ACTION_OF_UNKNOWN uint8 = iota
	POLICY_ACTION_OF_PASS
	POLICY_ACTION_OF_DROP
)

const (
	POLICY_CHAIN_PRIO_OF_HIGH uint8 = iota
	POLICY_CHAIN_PRIO_OF_MEDIUM
	POLICY_CHAIN_PRIO_OF_LOW
	POLICY_CHAIN_PRIO_OF_MAX
)

type Action uint8

type RuleAttr struct {
	Action  Action
	Counter uint64
}

type RuleCell struct {
	Prio     uint8
	Id       base.AddrId
	Workload base.WorkloadId
	Role     base.WorkRole
	Group    base.WorkGroup
	Dir      base.Direction
	Method   base.Method
	Api      base.ApiService
}

type L7Key struct {
	Workload base.WorkloadId
	Role     base.WorkRole
	Group    base.WorkGroup
	Dir      base.Direction
	Method   base.Method
	Api      base.ApiService
}

type L3Key struct {
	Id     base.AddrId
	Dir    base.Direction
	Method base.Method
	Api    base.ApiService
}
