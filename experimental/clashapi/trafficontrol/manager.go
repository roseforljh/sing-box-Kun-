package trafficontrol

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/compatible"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/x/list"

	"github.com/gofrs/uuid/v5"
)

// OutboundTrafficCounter holds per-outbound traffic counters
type OutboundTrafficCounter struct {
	Upload   atomic.Int64
	Download atomic.Int64
}

type Manager struct {
	uploadTotal   atomic.Int64
	downloadTotal atomic.Int64

	connections             compatible.Map[uuid.UUID, Tracker]
	closedConnectionsAccess sync.Mutex
	closedConnections       list.List[TrackerMetadata]
	// process     *process.Process
	memory uint64

	// Per-outbound traffic counters
	outboundTraffic compatible.Map[string, *OutboundTrafficCounter]
}

func NewManager() *Manager {
	return &Manager{}
}

func (m *Manager) Join(c Tracker) {
	m.connections.Store(c.Metadata().ID, c)
}

func (m *Manager) Leave(c Tracker) {
	metadata := c.Metadata()
	_, loaded := m.connections.LoadAndDelete(metadata.ID)
	if loaded {
		metadata.ClosedAt = time.Now()
		m.closedConnectionsAccess.Lock()
		defer m.closedConnectionsAccess.Unlock()
		if m.closedConnections.Len() >= 1000 {
			m.closedConnections.PopFront()
		}
		m.closedConnections.PushBack(metadata)
	}
}

func (m *Manager) PushUploaded(size int64) {
	m.uploadTotal.Add(size)
}

func (m *Manager) PushDownloaded(size int64) {
	m.downloadTotal.Add(size)
}

func (m *Manager) PushOutboundUploaded(outbound string, size int64) {
	if outbound == "" {
		return
	}
	counter, _ := m.outboundTraffic.LoadOrStore(outbound, &OutboundTrafficCounter{})
	counter.Upload.Add(size)
}

func (m *Manager) PushOutboundDownloaded(outbound string, size int64) {
	if outbound == "" {
		return
	}
	counter, _ := m.outboundTraffic.LoadOrStore(outbound, &OutboundTrafficCounter{})
	counter.Download.Add(size)
}

func (m *Manager) GetOutboundTraffic() map[string][2]int64 {
	result := make(map[string][2]int64)
	m.outboundTraffic.Range(func(tag string, counter *OutboundTrafficCounter) bool {
		result[tag] = [2]int64{counter.Upload.Load(), counter.Download.Load()}
		return true
	})
	return result
}

func (m *Manager) Total() (up int64, down int64) {
	return m.uploadTotal.Load(), m.downloadTotal.Load()
}

func (m *Manager) ConnectionsLen() int {
	return m.connections.Len()
}

func (m *Manager) Connections() []TrackerMetadata {
	var connections []TrackerMetadata
	m.connections.Range(func(_ uuid.UUID, value Tracker) bool {
		connections = append(connections, value.Metadata())
		return true
	})
	return connections
}

func (m *Manager) ClosedConnections() []TrackerMetadata {
	m.closedConnectionsAccess.Lock()
	defer m.closedConnectionsAccess.Unlock()
	return m.closedConnections.Array()
}

func (m *Manager) Connection(id uuid.UUID) Tracker {
	connection, loaded := m.connections.Load(id)
	if !loaded {
		return nil
	}
	return connection
}

func (m *Manager) Snapshot() *Snapshot {
	var connections []Tracker
	m.connections.Range(func(_ uuid.UUID, value Tracker) bool {
		if value.Metadata().OutboundType != C.TypeDNS {
			connections = append(connections, value)
		}
		return true
	})

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	m.memory = memStats.StackInuse + memStats.HeapInuse + memStats.HeapIdle - memStats.HeapReleased

	return &Snapshot{
		Upload:      m.uploadTotal.Load(),
		Download:    m.downloadTotal.Load(),
		Connections: connections,
		Memory:      m.memory,
	}
}

func (m *Manager) ResetStatistic() {
	m.uploadTotal.Store(0)
	m.downloadTotal.Store(0)
	m.outboundTraffic = compatible.Map[string, *OutboundTrafficCounter]{}
}

// CloseIdleConnections closes connections that have been idle for more than maxIdleSeconds.
// Returns the number of connections closed.
func (m *Manager) CloseIdleConnections(maxIdleSeconds int64) int {
	now := time.Now().UnixNano()
	threshold := maxIdleSeconds * int64(time.Second)
	closedCount := 0

	m.connections.Range(func(_ uuid.UUID, tracker Tracker) bool {
		metadata := tracker.Metadata()
		if metadata.LastActivityAt == nil {
			return true
		}
		lastActivity := metadata.LastActivityAt.Load()
		idleNanos := now - lastActivity
		if idleNanos > threshold {
			tracker.Close()
			closedCount++
		}
		return true
	})

	return closedCount
}

type Snapshot struct {
	Download    int64
	Upload      int64
	Connections []Tracker
	Memory      uint64
}

func (s *Snapshot) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"downloadTotal": s.Download,
		"uploadTotal":   s.Upload,
		"connections":   common.Map(s.Connections, func(t Tracker) TrackerMetadata { return t.Metadata() }),
		"memory":        s.Memory,
	})
}
