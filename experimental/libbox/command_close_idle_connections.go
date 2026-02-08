package libbox

import (
	"encoding/binary"
	"net"

	"github.com/sagernet/sing-box/experimental/clashapi"
	E "github.com/sagernet/sing/common/exceptions"
)

// CloseIdleConnections closes connections that have been idle for more than maxIdleSeconds.
// Returns the number of connections closed.
func (c *CommandClient) CloseIdleConnections(maxIdleSeconds int64) (int32, error) {
	conn, err := c.directConnect()
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	err = binary.Write(conn, binary.BigEndian, uint8(CommandCloseIdleConnections))
	if err != nil {
		return 0, err
	}

	err = binary.Write(conn, binary.BigEndian, maxIdleSeconds)
	if err != nil {
		return 0, err
	}

	var closedCount int32
	err = binary.Read(conn, binary.BigEndian, &closedCount)
	if err != nil {
		return 0, err
	}

	return closedCount, readError(conn)
}

func (s *CommandServer) handleCloseIdleConnections(conn net.Conn) error {
	var maxIdleSeconds int64
	err := binary.Read(conn, binary.BigEndian, &maxIdleSeconds)
	if err != nil {
		return E.Cause(err, "read maxIdleSeconds")
	}

	service := s.service
	if service == nil {
		binary.Write(conn, binary.BigEndian, int32(0))
		return writeError(conn, E.New("service not ready"))
	}

	clashServer := service.clashServer
	if clashServer == nil {
		binary.Write(conn, binary.BigEndian, int32(0))
		return writeError(conn, E.New("clash server not available"))
	}

	trafficManager := clashServer.(*clashapi.Server).TrafficManager()
	closedCount := trafficManager.CloseIdleConnections(maxIdleSeconds)

	err = binary.Write(conn, binary.BigEndian, int32(closedCount))
	if err != nil {
		return err
	}

	return writeError(conn, nil)
}
