package protocol

// Implement the unmarshal
type ProtoType interface {
	Unmarshal([]byte) error
}

type Trans interface {
	TransmissionSDK(ProtoType, bool) error
}

type PoolGet = func() ProtoType
