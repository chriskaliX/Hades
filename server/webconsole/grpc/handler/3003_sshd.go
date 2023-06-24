package handler

import (
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"

	utilcache "k8s.io/apimachinery/pkg/util/cache"
)

type Sshd struct {
	c *utilcache.LRUExpireCache
}

var _ Event = (*Sshd)(nil)

func (s *Sshd) ID() int32 { return 3003 }

func (s *Sshd) Name() string { return "ssh_log" }

func (s *Sshd) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	mapper := make(map[string]interface{})
	for k, v := range m {
		mapper[k] = v
	}
	DefaultWorker.Add(s.ID(), req.AgentID, mapper)
	return nil
}

// ssh alarm
// single ip: within 5 mins, 5 failed
// multi ip: within 5 mins, 5 failed
// For now, just a demo
func (s *Sshd) incr(m map[string]string, req *pb.RawData) error {
	// item, ok := s.c.Get(req.AgentID)
	// if !ok {
	// 	var init int = 1
	// 	s.c.Add(req.AgentID, init, 120*time.Second)
	// }
	// s.c.Update(req.AgentID, item.(int)+1)
	return nil
}

func init() {
	RegistEvent(&Sshd{
		c: utilcache.NewLRUExpireCache(1024 * 8),
	})
}
