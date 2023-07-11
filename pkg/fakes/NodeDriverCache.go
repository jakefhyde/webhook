// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3 (interfaces: NodeCache)

// Package fakes is a generated GoMock package.
package fakes

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v30 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	labels "k8s.io/apimachinery/pkg/labels"
)

// MockNodeCache is a mock of NodeCache interface.
type MockNodeCache struct {
	ctrl     *gomock.Controller
	recorder *MockNodeCacheMockRecorder
}

// MockNodeCacheMockRecorder is the mock recorder for MockNodeCache.
type MockNodeCacheMockRecorder struct {
	mock *MockNodeCache
}

// NewMockNodeCache creates a new mock instance.
func NewMockNodeCache(ctrl *gomock.Controller) *MockNodeCache {
	mock := &MockNodeCache{ctrl: ctrl}
	mock.recorder = &MockNodeCacheMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockNodeCache) EXPECT() *MockNodeCacheMockRecorder {
	return m.recorder
}

// AddIndexer mocks base method.
func (m *MockNodeCache) AddIndexer(arg0 string, arg1 v30.NodeIndexer) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AddIndexer", arg0, arg1)
}

// AddIndexer indicates an expected call of AddIndexer.
func (mr *MockNodeCacheMockRecorder) AddIndexer(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddIndexer", reflect.TypeOf((*MockNodeCache)(nil).AddIndexer), arg0, arg1)
}

// Get mocks base method.
func (m *MockNodeCache) Get(arg0, arg1 string) (*v3.Node, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", arg0, arg1)
	ret0, _ := ret[0].(*v3.Node)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockNodeCacheMockRecorder) Get(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockNodeCache)(nil).Get), arg0, arg1)
}

// GetByIndex mocks base method.
func (m *MockNodeCache) GetByIndex(arg0, arg1 string) ([]*v3.Node, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByIndex", arg0, arg1)
	ret0, _ := ret[0].([]*v3.Node)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByIndex indicates an expected call of GetByIndex.
func (mr *MockNodeCacheMockRecorder) GetByIndex(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByIndex", reflect.TypeOf((*MockNodeCache)(nil).GetByIndex), arg0, arg1)
}

// List mocks base method.
func (m *MockNodeCache) List(arg0 string, arg1 labels.Selector) ([]*v3.Node, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List", arg0, arg1)
	ret0, _ := ret[0].([]*v3.Node)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// List indicates an expected call of List.
func (mr *MockNodeCacheMockRecorder) List(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockNodeCache)(nil).List), arg0, arg1)
}