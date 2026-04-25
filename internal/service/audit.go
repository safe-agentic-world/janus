package service

import "github.com/safe-agentic-world/nomos/internal/audit"

func (s *Service) RecordAuditEvent(event audit.Event) error {
	if s == nil || s.recorder == nil {
		return nil
	}
	return s.recorder.WriteEvent(event)
}
