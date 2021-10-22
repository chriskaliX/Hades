package grpctrans

import (
	"context"
	"errors"
	"fmt"
	pb "hadeserver/grpctrans/protobuf"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/peer"
)

type TransferHandler struct{}

func (h *TransferHandler) Transfer(stream pb.Transfer_TransferServer) error {
	// -- 字节这里写了连接池上限, 我调研一下有没有原生一点的方法 --
	// maxConcurrentStreams() - 这个不是真正限制的
	if err := GlobalGRPCPool.CheckLimit(); err != nil {
		return err
	}

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

	// 开始创建 Connection
	createAt := time.Now().UnixNano() / (1000 * 1000 * 1000)
	ctx, cancelFunc := context.WithCancel(context.Background())
	connection := Connection{
		AgentID:     agentID,
		Addr:        addr,
		CreateAt:    createAt,
		CommandChan: make(chan *pb.Command),
		Ctx:         ctx,
		CancelFunc:  cancelFunc,
	}

	err = GlobalGRPCPool.Add(agentID, &connection)
	if err != nil {
		return err
	}

	// 退出删除 agentID
	defer GlobalGRPCPool.Delete(agentID)

	// 接收到停止信号退出
	<-connection.Ctx.Done()
	return nil
}

func receiveData(stream pb.Transfer_TransferServer, conn *Connection) {
	defer conn.CancelFunc()
	for {
		select {
		case <-conn.Ctx.Done():
			return
		default:
			data, err := stream.Recv()
			if err != nil {
				return
			}
			handleData(data)
		}
	}
}

func handleData(req *pb.RawData) {
	timePkg := fmt.Sprintf("%d", req.Timestamp)
	inIPv4List := strings.Join(req.IntranetIPv4, ",")
	inIPv6List := strings.Join(req.IntranetIPv6, ",")

	for k, v := range req.GetPkg() {
		tmp, ok := v.Message["data_type"]
		if !ok {
			continue
		}
		dataType, err := strconv.Atoi(strings.TrimSpace(tmp))
		if err != nil {
			continue
		}
		fMessage := req.GetPkg()[k].Message
		fMessage["agent_id"] = req.AgentID
		fMessage["time_pkg"] = timePkg
		fMessage["hostname"] = req.Hostname
		fMessage["version"] = req.Version
		fMessage["in_ipv4_list"] = inIPv4List
		fMessage["in_ipv6_list"] = inIPv6List

		switch dataType {
		case 1:
			//parse the heartbeat data
			parseHeartBeat(fMessage, req)
		}
	}
}

func parseHeartBeat(hb map[string]string, req *pb.RawData) {
	agentID := req.AgentID
	conn, err := GlobalGRPCPool.Get(agentID)
	if err != nil {
		return
	}

	clearConn(conn)

	strCPU, ok := hb["cpu"]
	if ok {
		if cpu, err := strconv.ParseFloat(strCPU, 64); err == nil {
			conn.Cpu = cpu
		}
	}

	strIO, ok := hb["io"]
	if ok {
		if io, err := strconv.ParseFloat(strIO, 64); err == nil {
			conn.IO = io
		}
	}

	strMem, ok := hb["memory"]
	if ok {
		if mem, err := strconv.ParseInt(strMem, 10, 64); err == nil {
			conn.Memory = mem
		}
	}

	strSlab, ok := hb["slab"]
	if ok {
		if slab, err := strconv.ParseInt(strSlab, 10, 64); err == nil {
			conn.Slab = slab
		}
	}

	conn.HostName = req.Hostname
	conn.Version = req.Version
	if req.IntranetIPv4 != nil {
		conn.IntranetIPv4 = req.IntranetIPv4
	}

	if req.IntranetIPv6 != nil {
		conn.IntranetIPv6 = req.IntranetIPv6
	}

	//last heartbeat time get from server
	conn.LastHeartBeatTime = time.Now().Unix()
}

func clearConn(conn *Connection) {
	conn.Cpu = 0
	conn.IO = 0
	conn.Memory = 0
	conn.Slab = 0
	conn.LastHeartBeatTime = 0
	conn.Version = ""
	conn.HostName = ""
	conn.IntranetIPv4 = make([]string, 0)
	conn.IntranetIPv6 = make([]string, 0)
}
