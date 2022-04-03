package event

type Event interface {
	// Get the status
	Status() bool
	// Set the status
	SetStatus(bool)
	// Get interval of event
	Interval() int
	SetInterval(int)
	// Get the data_type field
	DataType() int
	// Run the task and get the result
	Run() (string, error)
}
