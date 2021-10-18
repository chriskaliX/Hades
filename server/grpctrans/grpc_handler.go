package grpctrans

import (
	pb "hadeserver/grpctrans/protobuf"
)

type TransferHandler struct {
}

func (h *TransferHandler) Transfer(stream pb.Transfer_TransferServer) error {
	return nil
}
