package libbox

import (
	"sync"
	"time"

	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/experimental/clashapi"
	"github.com/sagernet/sing-box/experimental/clashapi/trafficontrol"
	"github.com/sagernet/sing/service/pause"
)

const kunBoxVersionSuffix = "kunbox-minimal"

var currentStartedService struct {
	sync.RWMutex
	value *daemon.StartedService
}

func setCurrentStartedService(startedService *daemon.StartedService) {
	currentStartedService.Lock()
	currentStartedService.value = startedService
	currentStartedService.Unlock()
}

func clearCurrentStartedService(startedService *daemon.StartedService) {
	currentStartedService.Lock()
	if currentStartedService.value == startedService {
		currentStartedService.value = nil
	}
	currentStartedService.Unlock()
}

func currentInstance() *daemon.Instance {
	currentStartedService.RLock()
	startedService := currentStartedService.value
	currentStartedService.RUnlock()
	if startedService == nil {
		return nil
	}
	return startedService.Instance()
}

func currentTrafficManager(instance *daemon.Instance) *trafficontrol.Manager {
	if instance == nil {
		return nil
	}
	clashServer, isClashServer := instance.ClashServer().(*clashapi.Server)
	if !isClashServer {
		return nil
	}
	return clashServer.TrafficManager()
}

func currentPauseManager(instance *daemon.Instance) pause.Manager {
	if instance == nil {
		return nil
	}
	return instance.PauseManager()
}

func activeConnectionCount(instance *daemon.Instance) int {
	connectionCount := 0
	if instance != nil && instance.ConnectionManager() != nil {
		connectionCount = instance.ConnectionManager().Count()
	}
	trafficManager := currentTrafficManager(instance)
	if trafficManager != nil && trafficManager.ConnectionsLen() > connectionCount {
		connectionCount = trafficManager.ConnectionsLen()
	}
	return connectionCount
}

func closeTrackedConnections(instance *daemon.Instance) int64 {
	trafficManager := currentTrafficManager(instance)
	if trafficManager == nil {
		return 0
	}
	snapshot := trafficManager.Snapshot()
	if snapshot == nil || len(snapshot.Connections) == 0 {
		return 0
	}
	closedCount := int64(0)
	for _, connection := range snapshot.Connections {
		if connection == nil {
			continue
		}
		if connection.Close() == nil {
			closedCount++
		}
	}
	return closedCount
}

func resetRuntimeNetwork(instance *daemon.Instance, resetSystem bool) {
	if instance == nil {
		return
	}
	if instance.ConnectionManager() != nil {
		instance.ConnectionManager().CloseAll()
	}
	if box := instance.Box(); box != nil {
		if router := box.Router(); router != nil {
			router.ResetNetwork()
		}
		if resetSystem {
			if networkManager := box.Network(); networkManager != nil {
				networkManager.ResetNetwork()
			}
		}
	}
}

func GetKunBoxVersion() string {
	return Version() + "+" + kunBoxVersionSuffix
}

func CloseAllTrackedConnections() int64 {
	return closeTrackedConnections(currentInstance())
}

func CloseIdleConnections(idleMillis int64) int64 {
	instance := currentInstance()
	trafficManager := currentTrafficManager(instance)
	if trafficManager == nil {
		return 0
	}
	return trafficManager.CloseIdleConnections(time.Duration(idleMillis) * time.Millisecond)
}

func GetConnectionCount() int64 {
	return int64(activeConnectionCount(currentInstance()))
}

func CheckNetworkRecoveryNeeded() bool {
	instance := currentInstance()
	if instance == nil {
		return false
	}
	if pauseManager := currentPauseManager(instance); pauseManager != nil && pauseManager.IsDevicePaused() {
		return false
	}
	if activeConnectionCount(instance) == 0 {
		return false
	}
	box := instance.Box()
	if box == nil || box.Network() == nil {
		return false
	}
	return box.Network().DefaultNetworkInterface() == nil
}

func RecoverNetworkAuto() bool {
	instance := currentInstance()
	if instance == nil || !CheckNetworkRecoveryNeeded() {
		return false
	}
	closeTrackedConnections(instance)
	resetRuntimeNetwork(instance, true)
	return true
}

func ResetAllConnections(resetSystem bool) {
	instance := currentInstance()
	if instance == nil {
		return
	}
	closeTrackedConnections(instance)
	resetRuntimeNetwork(instance, resetSystem)
}
