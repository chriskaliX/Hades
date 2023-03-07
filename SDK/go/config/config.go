package config

const (
	TypePluginError = 1011
)

// Field information
const (
	FieldInvalid  = "-1"
	FieldError    = "-2"
	FieldOverrate = "-3"
)

// DataType
const (
	DTAgentStatus  = 1
	DTPluginStatus = 2

	// Linux
	DTMemfdCreate           = 614
	DTExecveAt              = 698
	DTExecve                = 700
	DTCommitCreds           = 1011
	DTPrctl                 = 1020
	DTPtrace                = 1021
	DTSecuritySocketConnect = 1022
	DTSecuritySocketBind    = 1024
	DTUdpRecvmsg            = 1025
	DTDoInitModule          = 1026
	DTKernelReadFile        = 1027
	DTSecurityInodeCreate   = 1028
	DTSecuritySbMount       = 1029
	DTCallUsermodehelper    = 1030
	DTSecurityFileIoctl     = 1031
)

// Task
const (
	TaskShutdown int32 = 0
	TaskUpdate   int32 = 1
	TaskSetenv   int32 = 2
	TaskRestart  int32 = 3
)
