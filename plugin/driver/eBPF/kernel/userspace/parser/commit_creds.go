package parser

import (
	"agent/global/structs"
	"encoding/binary"
	"io"
	"strings"
)

type SlimCred struct {
	Uid            uint32 /* real UID of the task */
	Gid            uint32 /* real GID of the task */
	Suid           uint32 /* saved UID of the task */
	Sgid           uint32 /* saved GID of the task */
	Euid           uint32 /* effective UID of the task */
	Egid           uint32 /* effective GID of the task */
	Fsuid          uint32 /* UID for VFS ops */
	Fsgid          uint32 /* GID for VFS ops */
	UserNamespace  uint32 /* User Namespace of the of the event */
	SecureBits     uint32 /* SUID-less security management */
	CapInheritable uint64 /* caps our children can inherit */
	CapPermitted   uint64 /* caps we're permitted */
	CapEffective   uint64 /* caps we can actually use */
	CapBounding    uint64 /* capability bounding set */
	CapAmbient     uint64 /* Ambient capability set */
}

func CommitCreds(buf io.Reader, process *structs.Process) error {
	var (
		index uint8
	)

	if err := binary.Read(buf, binary.LittleEndian, &index); err != nil {
		return err
	}

	old_cred := SlimCred{}
	if err := binary.Read(buf, binary.LittleEndian, &old_cred); err != nil {
		return err
	}

	if err := binary.Read(buf, binary.LittleEndian, &index); err != nil {
		return err
	}

	new_cred := SlimCred{}
	if err := binary.Read(buf, binary.LittleEndian, &new_cred); err != nil {
		return err
	}

	var err error
	pid_tree := make([]string, 0)
	if pid_tree, err = ParsePidTree(buf); err != nil {
		return err
	}
	process.PidTree = strings.Join(pid_tree, "<")

	return nil
}
