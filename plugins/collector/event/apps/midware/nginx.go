package midware

type Nginx struct {
	Version string `json:"version"`
}

func (Nginx) Name() string { return "nginx" }
