package handler

import (
	"fmt"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type Sshd struct{}

var _ Event = (*Sshd)(nil)

func (s *Sshd) ID() int32 { return 3003 }

func (s *Sshd) Name() string { return "ssh_log" }

func (s *Sshd) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	mapper := make(map[string]interface{})
	for k, v := range m {
		mapper[k] = v
	}
	fmt.Println(mapper)
	// DefaultWorker.Add(s.ID(), req.AgentID, mapper)
	return nil
}

func init() { RegistEvent(&Sshd{}) }
