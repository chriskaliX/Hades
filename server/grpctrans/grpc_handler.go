package grpctrans

import (
	"google.golang.org/grpc/peer"
	pb "hadeserver/grpctrans/protobuf"
)

type TransferHandler struct {
}

func (h *TransferHandler) Transfer(stream pb.Transfer_TransferServer) error {
	// -- 字节这里写了连接池上限, 我调研一下有没有原生一点的方法 --

	// AgentID 没有在每个包里都重复的必要, 所以仅取第一次, 让第一次回连的时候带上
	data, err := stream.Recv()
	if err != nil {
		// todo: log
		return err
	}
	agentID := data.AgentID

	// peer 获取端对端IP, 如果后期网关则... http://xiaorui.cc/archives/6892
	p, ok := peer.FromContext(stream.Context())
	if !ok {
		// todo: log
		return errors.New("client ip get error")
	}
	addr := p.Addr.String()
	// 到这真正连接成功了, 没有问题, 再进行下一步的数据交互


	return nil
}
