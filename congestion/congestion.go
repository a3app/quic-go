// Package congestion selects the congestion controller of a connection.
// Use it with Conn.SetCongestionControl.
package congestion

import (
	"github.com/quic-go/quic-go/internal/congestion"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

// An Algorithm makes the congestion controller for one connection.
type Algorithm struct{ make congestion.Maker }

// Maker is for quic-go itself.
func (a Algorithm) Maker() congestion.Maker { return a.make }

// Reno is quic-go's default.
func Reno() Algorithm {
	return Algorithm{func(rtt *utils.RTTStats, mss protocol.ByteCount) congestion.SendAlgorithmWithDebugInfos {
		return congestion.NewCubicSender(congestion.DefaultClock{}, rtt, &utils.ConnectionStats{}, mss, true, nil)
	}}
}

// BBR paces at the measured bottleneck bandwidth and does not treat loss
// as a signal.
func BBR() Algorithm {
	return Algorithm{congestion.NewBBRSender}
}

// Fixed sends at bytesPerSecond, a little faster under loss so that about
// that much arrives, and never slows down. Use only with a rate the path
// is known to carry.
func Fixed(bytesPerSecond uint64) Algorithm {
	return Algorithm{func(rtt *utils.RTTStats, mss protocol.ByteCount) congestion.SendAlgorithmWithDebugInfos {
		return congestion.NewFixedSender(rtt, mss, bytesPerSecond)
	}}
}
