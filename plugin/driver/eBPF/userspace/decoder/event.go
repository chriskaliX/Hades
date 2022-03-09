package decoder

type Event interface {
	ID() uint32
	Parse() (error)
	String() string
	GetExe() string
}
