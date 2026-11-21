package vpn

type Emitter func(event string, data any)

func (m *Manager) SetEmitter(emitter Emitter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.emitter = emitter
}

// emit must be called without m.mu held.
func (m *Manager) emit(event string, data any) {
	m.mu.RLock()
	emitter := m.emitter
	m.mu.RUnlock()
	if emitter == nil {
		return
	}
	emitter(event, data)
}
