// Code generated by mockery v2.15.0. DO NOT EDIT.

package mocks

import (
	env "github.com/DataDog/datadog-agent/pkg/compliance/checks/env"
	eval "github.com/DataDog/datadog-agent/pkg/compliance/eval"

	event "github.com/DataDog/datadog-agent/pkg/compliance/event"

	mock "github.com/stretchr/testify/mock"
)

// Env is an autogenerated mock type for the Env type
type Env struct {
	mock.Mock
}

// AuditClient provides a mock function with given fields:
func (_m *Env) AuditClient() env.AuditClient {
	ret := _m.Called()

	var r0 env.AuditClient
	if rf, ok := ret.Get(0).(func() env.AuditClient); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(env.AuditClient)
		}
	}

	return r0
}

// ConfigDir provides a mock function with given fields:
func (_m *Env) ConfigDir() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// DockerClient provides a mock function with given fields:
func (_m *Env) DockerClient() env.DockerClient {
	ret := _m.Called()

	var r0 env.DockerClient
	if rf, ok := ret.Get(0).(func() env.DockerClient); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(env.DockerClient)
		}
	}

	return r0
}

// DumpInputPath provides a mock function with given fields:
func (_m *Env) DumpInputPath() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// EtcGroupPath provides a mock function with given fields:
func (_m *Env) EtcGroupPath() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// EvaluateFromCache provides a mock function with given fields: e
func (_m *Env) EvaluateFromCache(e eval.Evaluatable) (interface{}, error) {
	ret := _m.Called(e)

	var r0 interface{}
	if rf, ok := ret.Get(0).(func(eval.Evaluatable) interface{}); ok {
		r0 = rf(e)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(interface{})
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(eval.Evaluatable) error); ok {
		r1 = rf(e)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Hostname provides a mock function with given fields:
func (_m *Env) Hostname() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// IsLeader provides a mock function with given fields:
func (_m *Env) IsLeader() bool {
	ret := _m.Called()

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// KubeClient provides a mock function with given fields:
func (_m *Env) KubeClient() env.KubeClient {
	ret := _m.Called()

	var r0 env.KubeClient
	if rf, ok := ret.Get(0).(func() env.KubeClient); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(env.KubeClient)
		}
	}

	return r0
}

// MaxEventsPerRun provides a mock function with given fields:
func (_m *Env) MaxEventsPerRun() int {
	ret := _m.Called()

	var r0 int
	if rf, ok := ret.Get(0).(func() int); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int)
	}

	return r0
}

// NodeLabels provides a mock function with given fields:
func (_m *Env) NodeLabels() map[string]string {
	ret := _m.Called()

	var r0 map[string]string
	if rf, ok := ret.Get(0).(func() map[string]string); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string]string)
		}
	}

	return r0
}

// NormalizeToHostRoot provides a mock function with given fields: path
func (_m *Env) NormalizeToHostRoot(path string) string {
	ret := _m.Called(path)

	var r0 string
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(path)
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// ProvidedInput provides a mock function with given fields: ruleID
func (_m *Env) ProvidedInput(ruleID string) eval.RegoInputMap {
	ret := _m.Called(ruleID)

	var r0 eval.RegoInputMap
	if rf, ok := ret.Get(0).(func(string) eval.RegoInputMap); ok {
		r0 = rf(ruleID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(eval.RegoInputMap)
		}
	}

	return r0
}

// RelativeToHostRoot provides a mock function with given fields: path
func (_m *Env) RelativeToHostRoot(path string) string {
	ret := _m.Called(path)

	var r0 string
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(path)
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Reporter provides a mock function with given fields:
func (_m *Env) Reporter() event.Reporter {
	ret := _m.Called()

	var r0 event.Reporter
	if rf, ok := ret.Get(0).(func() event.Reporter); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(event.Reporter)
		}
	}

	return r0
}

// ShouldSkipRegoEval provides a mock function with given fields:
func (_m *Env) ShouldSkipRegoEval() bool {
	ret := _m.Called()

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

type mockConstructorTestingTNewEnv interface {
	mock.TestingT
	Cleanup(func())
}

// NewEnv creates a new instance of Env. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewEnv(t mockConstructorTestingTNewEnv) *Env {
	mock := &Env{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
