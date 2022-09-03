//go:build windows

package agent

func New() (agent *Agent) {
	agent = &Agent{
		Product: Product,
		Version: Version,
		OS:      runtime.GOOS,
	}
	var err error
	agent.Context, agent.Cancel = context.WithCancel(context.Background())
	if agent.Workdir, err = os.Getwd(); err != nil {
		agent.Workdir = config.HADES_PIDPATH
	}
	agent.genUUIDWin()
	return
}

type win32_ComputerSystemProduct struct {
	UUID string
}

func (a *Agent) genUUIDWin() {
	var dst []win32_ComputerSystemProduct
	q := "SELECT UUID FROM Win32_ComputerSystemProduct"
	err := wmi.Query(q, &dst)
	if err == nil {
		a.ID = dst[0].UUID
	}
}
