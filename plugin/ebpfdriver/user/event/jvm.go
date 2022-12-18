package event

// var DefaultJVM = &JVM{}

// var _ decoder.Event = (*JVM)(nil)

// type JVM struct {
// 	// 	Exe                string `json:"-"`
// }

// func (JVM) ID() uint32 {
// 	return 2001
// }

// func (JVM) String() string {
// 	return "JVM_hook"
// }

// func (j *JVM) GetExe() string {
// 	return j.Exe
// }

// func (j *JVM) Parse() (err error) {
// 	return
// }

// func (j JVM) GetProbe() []*manager.Probe {
// 	return []*manager.Probe{
// 		{
// 			UID:              "UprobeJVMGC",
// 			Section:          "uprobe/JVM_GC",
// 			EbpfFuncName:     "uprobe_JVM_GC",
// 			AttachToFuncName: "JVM_GC",
// 			BinaryPath:       "/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/amd64/server/libjvm.so",
// 		},
// 	}
// }
