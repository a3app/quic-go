package congestion

import (
	"math/rand/v2"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

// BBR (version 1) paces at the bottleneck bandwidth it measures and keeps
// about two bandwidth-delay products in flight. Loss is not a signal: a
// lossy path keeps its rate as long as acks show the bandwidth is there.
//
// Bandwidth comes from delivery-rate samples: for each acked packet, bytes
// delivered since it was sent over the time that took. The estimate is the
// largest sample of the last ten round trips in which the path, not the
// app, set the pace: a quiet spell (the peer uploading, a page being read)
// keeps the old estimate instead of letting it shrink to the trickle. Min RTT is the smallest RTT of
// the last ten seconds; when it goes stale the sender drains to four packets
// for 200 ms (ProbeRTT) to measure it again.

type bbrMode uint8

const (
	bbrStartup  bbrMode = iota // double the rate each round until bandwidth stops growing
	bbrDrain                   // empty the queue Startup built
	bbrProbeBW                 // cruise at the estimate, probe up and down in turn
	bbrProbeRTT                // fall to four packets to refresh min RTT
)

const (
	bbrHighGain     = 2.885 // 2/ln2: the smallest gain that doubles delivery every round
	bbrCwndGain     = 2.0
	bbrBwRounds     = 10
	bbrMinRTTWindow = 10 * time.Second
	bbrProbeRTTTime = 200 * time.Millisecond
	bbrMinCwnd      = 4 // packets
)

// ProbeBW pacing gains, one phase per min RTT.
var bbrCycle = [...]float64{1.25, 0.75, 1, 1, 1, 1, 1, 1}

// bbrPacket is what the sender remembers about a packet until it is acked or lost.
type bbrPacket struct {
	size       protocol.ByteCount
	sent       monotime.Time
	firstSent  monotime.Time // send time of the newest acked packet when this one left
	delivered  protocol.ByteCount
	deliveredT monotime.Time
	appLimited bool
}

type bbrSender struct {
	rtt   *utils.RTTStats
	pacer *pacer
	mss   protocol.ByteCount

	sent       map[protocol.PacketNumber]bbrPacket
	inflight   protocol.ByteCount
	delivered  protocol.ByteCount
	deliveredT monotime.Time
	firstSent  monotime.Time
	appLimited protocol.ByteCount // app-limited until delivered passes this; 0 = not

	round     uint64
	nextRound protocol.ByteCount
	bwRound   uint64   // rounds that ended on a sample the app did not limit
	bw        bwFilter // bytes/s, indexed by bwRound

	minRTT      time.Duration
	minRTTStamp monotime.Time

	mode       bbrMode
	full       bool   // Startup found the bottleneck
	fullBw     uint64 // best bandwidth while checking for it
	fullRounds int    // rounds without 25 % growth
	cycle      int    // ProbeBW phase
	cycleStamp monotime.Time
	probeEnd   monotime.Time // ProbeRTT: earliest exit; zero until inflight is low
	probeRound uint64        // ProbeRTT: a round must also pass

	pacingGain float64
	cwnd       protocol.ByteCount
}

var _ SendAlgorithmWithDebugInfos = &bbrSender{}

// NewBBRSender starts in Startup with the initial window quic-go uses.
func NewBBRSender(rtt *utils.RTTStats, mss protocol.ByteCount) SendAlgorithmWithDebugInfos {
	b := &bbrSender{
		rtt:        rtt,
		mss:        mss,
		sent:       make(map[protocol.PacketNumber]bbrPacket),
		pacingGain: bbrHighGain,
		cwnd:       initialCongestionWindow * mss,
	}
	b.pacer = newPacer(func() Bandwidth {
		// The pacer adds 25 % headroom of its own; take it back out so the
		// gains below are the real ones.
		return Bandwidth(b.pacingRate()) * BytesPerSecond * 4 / 5
	})
	b.pacer.SetMaxDatagramSize(mss)
	return b
}

// pacingRate is bytes/s. Before the first sample it is the initial window
// per smoothed RTT, times the Startup gain.
func (b *bbrSender) pacingRate() uint64 {
	if bw := b.bw.max(b.bwRound); bw > 0 {
		return uint64(b.pacingGain * float64(bw))
	}
	srtt := b.rtt.SmoothedRTT()
	if srtt <= 0 {
		srtt = 100 * time.Millisecond
	}
	return uint64(bbrHighGain * float64(b.cwnd) / srtt.Seconds())
}

func (b *bbrSender) bdp(gain float64) protocol.ByteCount {
	bw := b.bw.max(b.bwRound)
	if bw == 0 || b.minRTT == 0 {
		return initialCongestionWindow * b.mss
	}
	return protocol.ByteCount(gain * float64(bw) * b.minRTT.Seconds())
}

func (b *bbrSender) OnPacketSent(t monotime.Time, _ protocol.ByteCount, pn protocol.PacketNumber, size protocol.ByteCount, retransmittable bool) {
	if !retransmittable {
		return
	}
	if b.inflight == 0 {
		b.firstSent, b.deliveredT = t, t
	}
	// A full bucket means nothing waited to be sent: the app, not the path,
	// sets the rate until what is in flight now is delivered.
	if b.pacer.Budget(t) >= b.pacer.maxBurstSize() && b.inflight+size < b.cwnd {
		b.appLimited = max(b.delivered+b.inflight+size, 1)
	}
	b.sent[pn] = bbrPacket{size, t, b.firstSent, b.delivered, b.deliveredT, b.appLimited != 0}
	b.inflight += size
	b.pacer.SentPacket(t, size)
}

func (b *bbrSender) OnPacketAcked(pn protocol.PacketNumber, _, _ protocol.ByteCount, now monotime.Time) {
	p, ok := b.sent[pn]
	if !ok {
		return
	}
	delete(b.sent, pn)
	b.inflight -= p.size
	b.delivered += p.size
	b.deliveredT = now
	b.firstSent = p.sent
	if b.appLimited != 0 && b.delivered > b.appLimited {
		b.appLimited = 0
	}

	roundStart := p.delivered >= b.nextRound
	if roundStart {
		b.nextRound = b.delivered
		b.round++
		if !p.appLimited {
			b.bwRound++
		}
	}
	// The slower of the send and ack rates over this packet's flight.
	if d := max(p.sent.Sub(p.firstSent), now.Sub(p.deliveredT)); d > 0 {
		rate := uint64(float64(b.delivered-p.delivered) / d.Seconds())
		if !p.appLimited || rate >= b.bw.max(b.bwRound) {
			b.bw.update(b.bwRound, rate)
		}
	}
	rtt := b.rtt.LatestRTT()
	stale := now.Sub(b.minRTTStamp) > bbrMinRTTWindow
	if rtt > 0 && (b.minRTT == 0 || rtt <= b.minRTT || stale) {
		b.minRTT, b.minRTTStamp = rtt, now
	}

	// Only a round the path paced can show that bandwidth stopped growing.
	if roundStart && !b.full && !p.appLimited {
		if bw := b.bw.max(b.bwRound); bw >= b.fullBw*5/4 {
			b.fullBw, b.fullRounds = bw, 0
		} else if b.fullRounds++; b.fullRounds >= 3 {
			b.full = true
		}
	}
	switch b.mode {
	case bbrStartup:
		if b.full {
			b.mode, b.pacingGain = bbrDrain, 1/bbrHighGain
		}
	case bbrDrain:
		if b.inflight <= b.bdp(1) {
			b.enterProbeBW(now)
		}
	case bbrProbeBW:
		g := bbrCycle[b.cycle]
		if now.Sub(b.cycleStamp) > b.minRTT || g < 1 && b.inflight <= b.bdp(1) {
			b.cycle = (b.cycle + 1) % len(bbrCycle)
			b.cycleStamp, b.pacingGain = now, bbrCycle[b.cycle]
		}
	}
	if stale && b.mode != bbrProbeRTT {
		b.mode, b.pacingGain, b.probeEnd = bbrProbeRTT, 1, 0
	}
	if b.mode == bbrProbeRTT {
		if b.probeEnd.IsZero() && b.inflight <= bbrMinCwnd*b.mss {
			b.probeEnd, b.probeRound = now.Add(bbrProbeRTTTime), b.round+1
		} else if !b.probeEnd.IsZero() && b.round >= b.probeRound && !now.Before(b.probeEnd) {
			b.minRTTStamp = now
			if b.full {
				b.enterProbeBW(now)
			} else {
				b.mode, b.pacingGain = bbrStartup, bbrHighGain
			}
		}
	}

	gain := bbrCwndGain
	if b.mode == bbrStartup {
		gain = bbrHighGain
	}
	target := b.bdp(gain) + 3*b.mss
	if b.full {
		b.cwnd = min(b.cwnd+p.size, target)
	} else if b.cwnd < target || b.delivered < initialCongestionWindow*b.mss {
		b.cwnd += p.size
	}
	b.cwnd = max(b.cwnd, bbrMinCwnd*b.mss)
}

// enterProbeBW starts the gain cycle at a random phase other than the
// drain one, so flows that share a bottleneck do not probe in step.
func (b *bbrSender) enterProbeBW(now monotime.Time) {
	b.mode, b.cycleStamp = bbrProbeBW, now
	b.cycle = rand.IntN(len(bbrCycle) - 1)
	if b.cycle >= 1 {
		b.cycle++
	}
	b.pacingGain = bbrCycle[b.cycle]
}

func (b *bbrSender) OnCongestionEvent(pn protocol.PacketNumber, lost, _ protocol.ByteCount) {
	if lost == 0 { // ECN mark: BBR v1 does not react
		return
	}
	if p, ok := b.sent[pn]; ok {
		delete(b.sent, pn)
		b.inflight -= p.size
	}
}

func (b *bbrSender) CanSend(inflight protocol.ByteCount) bool {
	if b.mode == bbrProbeRTT {
		return inflight < bbrMinCwnd*b.mss
	}
	return inflight < b.cwnd
}

func (b *bbrSender) TimeUntilSend(protocol.ByteCount) monotime.Time { return b.pacer.TimeUntilSend() }
func (b *bbrSender) HasPacingBudget(now monotime.Time) bool {
	return b.pacer.Budget(now) >= b.mss
}
func (b *bbrSender) MaybeExitSlowStart()                     {}
func (b *bbrSender) OnRetransmissionTimeout(bool)            {}
func (b *bbrSender) InSlowStart() bool                       { return b.mode == bbrStartup }
func (b *bbrSender) InRecovery() bool                        { return false }
func (b *bbrSender) GetCongestionWindow() protocol.ByteCount { return b.cwnd }
func (b *bbrSender) SetMaxDatagramSize(s protocol.ByteCount) {
	b.cwnd = b.cwnd / b.mss * s
	b.mss = s
	b.pacer.SetMaxDatagramSize(s)
}

// bwFilter keeps the largest sample of each of the last bbrBwRounds rounds.
type bwFilter struct {
	v, r [bbrBwRounds]uint64
}

func (f *bwFilter) update(round, bw uint64) {
	i := round % bbrBwRounds
	if f.r[i] != round {
		f.r[i], f.v[i] = round, 0
	}
	f.v[i] = max(f.v[i], bw)
}

func (f *bwFilter) max(round uint64) (m uint64) {
	for i := range f.v {
		if f.r[i]+bbrBwRounds > round {
			m = max(m, f.v[i])
		}
	}
	return m
}
