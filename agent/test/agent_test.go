package test

import (
	"agent/agent"
	"testing"
)

func TestAgent(t *testing.T) {
	agent := agent.New()
	t.Log(agent)
}
