package self_test

import (
	"bytes"
	"context"
	"io"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/congestion"
	"github.com/quic-go/quic-go/internal/synctest"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

// bottleneck carries the server's packets at rate bytes/s through a
// drop-tail queue of queue bytes, and drops a share loss of them at random
// first. rate 0 is unlimited. The client's packets pass untouched.
type bottleneck struct {
	simnet.PerfectRouter
	rate, queue int
	loss        float64

	mu   sync.Mutex
	free time.Time // when the link finishes what it already has
	peak int       // largest queue seen, bytes
}

func (b *bottleneck) SendPacket(p simnet.Packet) error {
	if p.From.String() != "1.0.0.2:9002" {
		return b.PerfectRouter.SendPacket(p)
	}
	if rand.Float64() < b.loss {
		return nil
	}
	if b.rate == 0 {
		return b.PerfectRouter.SendPacket(p)
	}
	b.mu.Lock()
	now := time.Now()
	start := now
	if b.free.After(now) {
		start = b.free
	}
	queued := int(start.Sub(now).Seconds() * float64(b.rate))
	if queued+len(p.Data) > b.queue {
		b.mu.Unlock()
		return nil
	}
	b.peak = max(b.peak, queued+len(p.Data))
	b.free = start.Add(time.Duration(float64(len(p.Data)) / float64(b.rate) * float64(time.Second)))
	wait := b.free.Sub(now)
	b.mu.Unlock()
	time.AfterFunc(wait, func() { b.PerfectRouter.SendPacket(p) })
	return nil
}

// download sends size bytes from server to client through b, with the
// server on a, and returns how long the client took to read them.
func download(t *testing.T, a congestion.Algorithm, rtt time.Duration, b *bottleneck, size int) time.Duration {
	t.Helper()
	var took time.Duration
	synctest.Test(t, func(t *testing.T) {
		clientConn, serverConn, closeFn := newSimnetLinkWithRouter(t, rtt, b)
		defer closeFn(t)

		ln, err := quic.Listen(serverConn, getTLSConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer ln.Close()
		data := bytes.Repeat([]byte{'x'}, size)
		sconn := make(chan *quic.Conn, 1)
		go func() {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			sconn <- conn
			conn.SetCongestionControl(a)
			str, err := conn.OpenStream()
			if err != nil {
				return
			}
			str.Write(data)
			str.Close()
		}()

		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		conn, err := quic.Dial(ctx, clientConn, serverConn.LocalAddr(), getTLSClientConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer conn.CloseWithError(0, "")
		str, err := conn.AcceptStream(ctx)
		require.NoError(t, err)
		start := time.Now()
		got, err := io.ReadAll(str)
		took = time.Since(start)
		require.NoError(t, err)
		require.Len(t, got, size)
		(<-sconn).CloseWithError(0, "")
	})
	return took
}

func TestCongestionOnLossyPath(t *testing.T) {
	const (
		rtt  = 80 * time.Millisecond
		loss = 0.05
		size = 4 << 20
		rate = 2 << 20 // bytes/s for fixed
	)
	reno := download(t, congestion.Reno(), rtt, &bottleneck{loss: loss}, size)
	bbr := download(t, congestion.BBR(), rtt, &bottleneck{loss: loss}, size)
	fixed := download(t, congestion.Fixed(rate), rtt, &bottleneck{loss: loss}, size)
	t.Logf("reno %v, bbr %v, fixed %v", reno, bbr, fixed)

	require.Less(t, bbr, reno/3, "bbr should not back off on random loss")
	want := time.Duration(float64(size) / rate * float64(time.Second))
	require.Greater(t, fixed, want*8/10, "fixed sent faster than agreed")
	require.Less(t, fixed, want*13/10+2*rtt, "fixed did not hold its rate under loss")
}

// TestBBRFindsBottleneck: on a 4 MB/s link with a queue of four BDPs BBR
// reaches most of the link and keeps the queue well below full, and random
// loss on that link does not slow it much.
func TestBBRFindsBottleneck(t *testing.T) {
	const (
		rtt   = 50 * time.Millisecond
		rate  = 4 << 20
		size  = 16 << 20
		queue = 4 * rate / 20 // four BDPs
	)
	reno := &bottleneck{rate: rate, queue: queue}
	bbr := &bottleneck{rate: rate, queue: queue}
	tr := download(t, congestion.Reno(), rtt, reno, size)
	tb := download(t, congestion.BBR(), rtt, bbr, size)
	t.Logf("reno %v peak queue %d KB, bbr %v peak queue %d KB", tr, reno.peak>>10, tb, bbr.peak>>10)

	ideal := time.Duration(float64(size) / rate * float64(time.Second))
	require.Less(t, tb, ideal*13/10, "bbr left the link idle")
	require.Less(t, bbr.peak, queue*3/4, "bbr filled the queue")

	// The same link losing 2 % at random still runs near its rate.
	tl := download(t, congestion.BBR(), rtt, &bottleneck{rate: rate, queue: queue, loss: 0.02}, size)
	t.Logf("bbr at 2 %% loss %v", tl)
	require.Less(t, tl, ideal*15/10, "bbr backed off on random loss")
}

// benchPattern mimics loft-bench on one connection: the server sends size,
// the client sends size, then the server sends size over 4 streams.
func benchPattern(t *testing.T, a congestion.Algorithm, rtt time.Duration, b *bottleneck, size int) (down, up, down4 time.Duration) {
	synctest.Test(t, func(t *testing.T) {
		clientConn, serverConn, closeFn := newSimnetLinkWithRouter(t, rtt, b)
		defer closeFn(t)
		ln, err := quic.Listen(serverConn, getTLSConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer ln.Close()
		data := bytes.Repeat([]byte{'x'}, size)
		sconn := make(chan *quic.Conn, 1)
		go func() {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			conn.SetCongestionControl(a)
			sconn <- conn
			// phase 1: one stream down
			str, _ := conn.OpenStream()
			str.Write(data)
			str.Close()
			// phase 2: read the client's upload
			in, err := conn.AcceptStream(context.Background())
			if err != nil {
				return
			}
			io.Copy(io.Discard, in)
			// phase 3: four streams down
			for i := 0; i < 4; i++ {
				go func() {
					s, _ := conn.OpenStream()
					s.Write(data[:size/4])
					s.Close()
				}()
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		conn, err := quic.Dial(ctx, clientConn, serverConn.LocalAddr(), getTLSClientConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer conn.CloseWithError(0, "")
		conn.SetCongestionControl(a)
		t0 := time.Now()
		s1, err := conn.AcceptStream(ctx)
		require.NoError(t, err)
		io.Copy(io.Discard, s1)
		down = time.Since(t0)
		t1 := time.Now()
		o, err := conn.OpenStreamSync(ctx)
		require.NoError(t, err)
		o.Write(data)
		o.Close()
		// up ends when the server has read it all: its first phase-3 stream arrives.
		var wg sync.WaitGroup
		first := true
		for i := 0; i < 4; i++ {
			s, err := conn.AcceptStream(ctx)
			require.NoError(t, err)
			if first {
				up, first = time.Since(t1), false
				t1 = time.Now()
			}
			wg.Add(1)
			go func() { defer wg.Done(); io.Copy(io.Discard, s) }()
		}
		wg.Wait()
		down4 = time.Since(t1)
		(<-sconn).CloseWithError(0, "")
	})
	return
}

// TestBBRAfterQuietSpell: a sender that sat app-limited (its peer was
// uploading, or it only sent acks) must not come out of it believing the
// trickle it saw is the path. Before the fix the second download took 17 s
// and the upload 16 s on this 6 MB/s path.
func TestBBRAfterQuietSpell(t *testing.T) {
	for i := 0; i < 3; i++ {
		down, up, down4 := benchPattern(t, congestion.BBR(), 150*time.Millisecond, &bottleneck{rate: 6 << 20, queue: 1 << 20, loss: 0.005}, 8<<20)
		t.Logf("down %v up %v down4 %v", down, up, down4)
		require.Less(t, up, 4*time.Second, "upload crawled after the client only acked")
		require.Less(t, down4, 4*time.Second, "download crawled after the server sat out the upload")
	}
}
