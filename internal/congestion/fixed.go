package congestion

import (
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

// The fixed-rate sender paces at a rate both ends agreed on and does not
// slow down on loss. It sends a little faster when packets are lost, so
// that about the agreed rate still arrives: up to a quarter more, at 20 %
// loss and above. The window allows two RTTs of that rate in flight.

const (
	fixedSlot     = time.Second // loss is counted per slot
	fixedSlots    = 4           // over the last few seconds
	fixedMinRatio = 0.8         // never send more than rate / 0.8
	fixedMinCwnd  = 16          // packets
)

type fixedSender struct {
	rate  uint64 // agreed, bytes/s
	rtt   *utils.RTTStats
	pacer *pacer
	mss   protocol.ByteCount

	acked, lost [fixedSlots]protocol.ByteCount
	stamp       [fixedSlots]int64 // slot number each counter belongs to
}

var _ SendAlgorithmWithDebugInfos = &fixedSender{}

// NewFixedSender sends at rate bytes/s.
func NewFixedSender(rtt *utils.RTTStats, mss protocol.ByteCount, rate uint64) SendAlgorithmWithDebugInfos {
	f := &fixedSender{rate: rate, rtt: rtt, mss: mss}
	f.pacer = newPacer(func() Bandwidth { return Bandwidth(f.sendRate()) * BytesPerSecond * 4 / 5 })
	f.pacer.SetMaxDatagramSize(mss)
	return f
}

// sendRate is the agreed rate divided by the share of bytes that arrive.
func (f *fixedSender) sendRate() uint64 {
	now := monotime.Now().Sub(0) / fixedSlot
	var a, l protocol.ByteCount
	for i := range f.stamp {
		if int64(now)-f.stamp[i] < fixedSlots {
			a, l = a+f.acked[i], l+f.lost[i]
		}
	}
	ratio := 1.0
	if a+l > 0 {
		ratio = max(float64(a)/float64(a+l), fixedMinRatio)
	}
	return uint64(float64(f.rate) / ratio)
}

func (f *fixedSender) count(now monotime.Time, acked, lost protocol.ByteCount) {
	s := int64(now.Sub(0) / fixedSlot)
	i := (s%fixedSlots + fixedSlots) % fixedSlots // monotonic time may be negative
	if f.stamp[i] != s {
		f.stamp[i], f.acked[i], f.lost[i] = s, 0, 0
	}
	f.acked[i] += acked
	f.lost[i] += lost
}

func (f *fixedSender) OnPacketSent(t monotime.Time, _ protocol.ByteCount, _ protocol.PacketNumber, size protocol.ByteCount, _ bool) {
	f.pacer.SentPacket(t, size)
}

func (f *fixedSender) OnPacketAcked(_ protocol.PacketNumber, size, _ protocol.ByteCount, now monotime.Time) {
	f.count(now, size, 0)
}

func (f *fixedSender) OnCongestionEvent(_ protocol.PacketNumber, lost, _ protocol.ByteCount) {
	if lost > 0 {
		f.count(monotime.Now(), 0, lost)
	}
}

func (f *fixedSender) GetCongestionWindow() protocol.ByteCount {
	rtt := f.rtt.SmoothedRTT()
	if rtt <= 0 {
		rtt = 100 * time.Millisecond
	}
	return max(protocol.ByteCount(2*float64(f.sendRate())*rtt.Seconds()), fixedMinCwnd*f.mss)
}

func (f *fixedSender) CanSend(inflight protocol.ByteCount) bool {
	return inflight < f.GetCongestionWindow()
}

func (f *fixedSender) TimeUntilSend(protocol.ByteCount) monotime.Time { return f.pacer.TimeUntilSend() }
func (f *fixedSender) HasPacingBudget(now monotime.Time) bool {
	return f.pacer.Budget(now) >= f.mss
}
func (f *fixedSender) MaybeExitSlowStart()          {}
func (f *fixedSender) OnRetransmissionTimeout(bool) {}
func (f *fixedSender) InSlowStart() bool            { return false }
func (f *fixedSender) InRecovery() bool             { return false }
func (f *fixedSender) SetMaxDatagramSize(s protocol.ByteCount) {
	f.mss = s
	f.pacer.SetMaxDatagramSize(s)
}
