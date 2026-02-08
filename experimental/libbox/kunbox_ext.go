package libbox

import (
	"strings"
	"sync"

	"github.com/sagernet/sing-box/experimental/clashapi"
)

// KunBox extension version
const KunBoxExtVersion = "1.0.0"

// Global service reference for extension APIs
var (
	globalService     *BoxService
	globalServiceLock sync.RWMutex
)

// SetGlobalService sets the global service reference for extension APIs
func SetGlobalService(service *BoxService) {
	globalServiceLock.Lock()
	defer globalServiceLock.Unlock()
	globalService = service
}

// ClearGlobalService clears the global service reference
func ClearGlobalService() {
	globalServiceLock.Lock()
	defer globalServiceLock.Unlock()
	globalService = nil
}

// GetKunBoxVersion returns the KunBox extension version
func GetKunBoxVersion() string {
	return KunBoxExtVersion
}

// ==================== Pause/Resume ====================

// IsPaused returns whether the service is paused
func IsPaused() bool {
	globalServiceLock.RLock()
	defer globalServiceLock.RUnlock()
	if globalService == nil {
		return false
	}
	return globalService.pauseManager.IsDevicePaused()
}

// PauseService pauses the service
func PauseService() {
	globalServiceLock.RLock()
	defer globalServiceLock.RUnlock()
	if globalService != nil {
		globalService.pauseManager.DevicePause()
	}
}

// ResumeService resumes the paused service
func ResumeService() {
	globalServiceLock.RLock()
	defer globalServiceLock.RUnlock()
	if globalService != nil {
		globalService.pauseManager.DeviceWake()
	}
}

// ==================== Connection Management ====================

// ResetAllConnections resets all tracked connections
// If closeConnections is true, it will close all connections
func ResetAllConnections(closeConnections bool) {
	globalServiceLock.RLock()
	defer globalServiceLock.RUnlock()
	if globalService == nil {
		return
	}

	// Reset network
	globalService.instance.Router().ResetNetwork()

	// Close all connections if requested
	if closeConnections && globalService.clashServer != nil {
		trafficManager := globalService.clashServer.(*clashapi.Server).TrafficManager()
		// Use CloseIdleConnections with 0 seconds to close all connections
		trafficManager.CloseIdleConnections(0)
	}
}

// CloseIdleConnections closes connections that have been idle for more than maxIdleSeconds
// Returns the number of connections closed
func CloseIdleConnections(maxIdleSeconds int64) int {
	globalServiceLock.RLock()
	defer globalServiceLock.RUnlock()
	if globalService == nil || globalService.clashServer == nil {
		return 0
	}

	trafficManager := globalService.clashServer.(*clashapi.Server).TrafficManager()
	return trafficManager.CloseIdleConnections(maxIdleSeconds)
}

// CloseAllTrackedConnections closes all tracked connections
// Returns the number of connections closed
func CloseAllTrackedConnections() int {
	return CloseIdleConnections(0)
}

// GetConnectionCount returns the number of active connections
func GetConnectionCount() int {
	globalServiceLock.RLock()
	defer globalServiceLock.RUnlock()
	if globalService == nil || globalService.clashServer == nil {
		return 0
	}

	trafficManager := globalService.clashServer.(*clashapi.Server).TrafficManager()
	return trafficManager.ConnectionsLen()
}

// ==================== Traffic Statistics ====================

// GetTrafficTotalUplink returns total upload bytes
func GetTrafficTotalUplink() int64 {
	globalServiceLock.RLock()
	defer globalServiceLock.RUnlock()
	if globalService == nil || globalService.clashServer == nil {
		return 0
	}

	trafficManager := globalService.clashServer.(*clashapi.Server).TrafficManager()
	up, _ := trafficManager.Total()
	return up
}

// GetTrafficTotalDownlink returns total download bytes
func GetTrafficTotalDownlink() int64 {
	globalServiceLock.RLock()
	defer globalServiceLock.RUnlock()
	if globalService == nil || globalService.clashServer == nil {
		return 0
	}

	trafficManager := globalService.clashServer.(*clashapi.Server).TrafficManager()
	_, down := trafficManager.Total()
	return down
}

// ResetTrafficStats resets traffic statistics (not supported, returns false)
func ResetTrafficStats() bool {
	// Traffic stats reset is not supported in current implementation
	return false
}

// ==================== Outbound Management ====================

// ListOutboundsString returns a newline-separated list of outbound tags
func ListOutboundsString() string {
	globalServiceLock.RLock()
	defer globalServiceLock.RUnlock()
	if globalService == nil {
		return ""
	}

	outbounds := globalService.instance.Outbound().Outbounds()
	var tags []string
	for _, outbound := range outbounds {
		tags = append(tags, outbound.Tag())
	}
	return strings.Join(tags, "\n")
}

// HasSelector returns whether there is a selector outbound
func HasSelector() bool {
	globalServiceLock.RLock()
	defer globalServiceLock.RUnlock()
	if globalService == nil {
		return false
	}

	outbounds := globalService.instance.Outbound().Outbounds()
	for _, outbound := range outbounds {
		if outbound.Type() == "selector" {
			return true
		}
	}
	return false
}

// SelectOutboundByTag selects an outbound by tag in the first selector group
func SelectOutboundByTag(tag string) bool {
	globalServiceLock.RLock()
	defer globalServiceLock.RUnlock()
	if globalService == nil {
		return false
	}

	outbounds := globalService.instance.Outbound().Outbounds()
	for _, outbound := range outbounds {
		if outbound.Type() == "selector" {
			if selector, ok := outbound.(interface{ SelectOutbound(string) bool }); ok {
				return selector.SelectOutbound(tag)
			}
		}
	}
	return false
}

// GetSelectedOutbound returns the currently selected outbound tag
func GetSelectedOutbound() string {
	globalServiceLock.RLock()
	defer globalServiceLock.RUnlock()
	if globalService == nil {
		return ""
	}

	outbounds := globalService.instance.Outbound().Outbounds()
	for _, outbound := range outbounds {
		if outbound.Type() == "selector" {
			if selector, ok := outbound.(interface{ Now() string }); ok {
				return selector.Now()
			}
		}
	}
	return ""
}

// ==================== Network Recovery ====================

// RecoverNetworkAuto automatically recovers network
func RecoverNetworkAuto() bool {
	globalServiceLock.RLock()
	defer globalServiceLock.RUnlock()
	if globalService == nil {
		return false
	}

	// Wake if paused
	if globalService.pauseManager.IsDevicePaused() {
		globalService.pauseManager.DeviceWake()
	}

	// Reset network
	globalService.instance.Router().ResetNetwork()
	return true
}

// CheckNetworkRecoveryNeeded checks if network recovery is needed
func CheckNetworkRecoveryNeeded() bool {
	globalServiceLock.RLock()
	defer globalServiceLock.RUnlock()
	if globalService == nil {
		return false
	}

	return globalService.pauseManager.IsDevicePaused()
}

// ==================== Per-Outbound Traffic ====================

// OutboundTraffic represents traffic for a single outbound
type OutboundTraffic struct {
	Tag      string
	Upload   int64
	Download int64
}

// OutboundTrafficIterator iterates over outbound traffic
type OutboundTrafficIterator struct {
	items []OutboundTraffic
	index int
}

// HasNext returns whether there are more items
func (i *OutboundTrafficIterator) HasNext() bool {
	return i.index < len(i.items)
}

// Next returns the next item
func (i *OutboundTrafficIterator) Next() *OutboundTraffic {
	if i.index >= len(i.items) {
		return nil
	}
	item := &i.items[i.index]
	i.index++
	return item
}

// GetTrafficByOutbound returns traffic statistics per outbound
func GetTrafficByOutbound() *OutboundTrafficIterator {
	globalServiceLock.RLock()
	defer globalServiceLock.RUnlock()
	if globalService == nil || globalService.clashServer == nil {
		return &OutboundTrafficIterator{}
	}

	// Note: Per-outbound traffic tracking is not implemented in standard sing-box
	// This returns an empty iterator for compatibility
	return &OutboundTrafficIterator{}
}
