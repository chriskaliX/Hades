package ebpf

import (
	"bytes"
	"context"
	"errors"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
)

type IEBPFProbe interface {
	// 统一实现
	Init(context.Context) error
	LoadKernel() error
	AttachProbe() error
	Run() error
	Close() error
}

type EBPFProbe struct {
	probeBytes  []byte
	opts        *ebpf.CollectionOptions
	probeObject IBPFProbeObject
	ctx         context.Context
	name        string
}

func (e *EBPFProbe) Init(ctx context.Context) error {
	e.ctx = ctx
	return nil
}

func (e *EBPFProbe) LoadKernel() error {
	reader := bytes.NewReader(e.probeBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return err
	}
	err = spec.LoadAndAssign(e.probeObject, e.opts)
	if err != nil {
		zap.S().Error(err)
		return err
	}
	return nil
}

// Object 对应的 Attach
func (e *EBPFProbe) AttachProbe() error {
	if e.probeObject == nil {
		return errors.New("probeObject nil")
	}
	return e.probeObject.AttachProbe()
}

func (e *EBPFProbe) Run() error {
	if err := e.LoadKernel(); err != nil {
		zap.S().Error(err.Error())
		return err
	}
	if err := e.AttachProbe(); err != nil {
		zap.S().Error(err.Error())
		return err
	}

	if e.probeObject == nil {
		zap.S().Error(errors.New("probeObject nil"))
		return errors.New("probeObject nil")
	}

	if err := e.probeObject.Read(); err != nil {
		zap.S().Error(err.Error())
		return err
	}
	return nil
}

func (e *EBPFProbe) Close() error {
	return e.probeObject.Close()
}
