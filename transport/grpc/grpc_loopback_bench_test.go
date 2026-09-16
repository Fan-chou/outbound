package grpc

import (
	"bytes"
	"context"
	"fmt"
	proto "github.com/daeuniverse/outbound/pkg/gun_proto"
	grpcpkg "google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"io"
	"net"
	"sort"
	"testing"
	"time"
)

type loopbackEchoServer struct {
	proto.UnimplementedGunServiceServer
}

func (*loopbackEchoServer) Tun(s proto.GunService_TunServer) error {
	for {
		h, err := s.Recv()
		if err != nil {
			return err
		}
		if err = s.Send(h); err != nil {
			return err
		}
	}
}

// This benchmark uses the real grpc marshal, HTTP/2 transport and TCP socket,
// including data verification and echo completion, rather than a no-op Send.
func BenchmarkGRPCRealLoopback(b *testing.B) {
	for _, size := range []int{64, 32768} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			defer l.Close()
			s := grpcpkg.NewServer()
			proto.RegisterGunServiceServer(s, &loopbackEchoServer{})
			defer s.Stop()
			go s.Serve(l)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			cc, err := grpcpkg.DialContext(ctx, l.Addr().String(), grpcpkg.WithTransportCredentials(insecure.NewCredentials()), grpcpkg.WithBlock())
			if err != nil {
				b.Fatal(err)
			}
			defer cc.Close()
			tun, err := proto.NewGunServiceClient(cc).Tun(ctx)
			if err != nil {
				b.Fatal(err)
			}
			c := NewClientConn(tun, cancel)
			defer c.Close()
			payload := bytes.Repeat([]byte{0x5a}, size)
			got := make([]byte, size)
			samples := make([]int64, 0, min(b.N, 10000))
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				start := time.Now()
				if n, err := c.Write(payload); err != nil || n != size {
					b.Fatalf("write=%d,%v", n, err)
				}
				if _, err := io.ReadFull(c, got); err != nil {
					b.Fatal(err)
				}
				if !bytes.Equal(payload, got) {
					b.Fatal("corrupt echo")
				}
				if len(samples) < cap(samples) {
					samples = append(samples, time.Since(start).Nanoseconds())
				}
			}
			b.StopTimer()
			sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
			if len(samples) > 0 {
				b.ReportMetric(float64(samples[(len(samples)-1)*99/100])/1000, "p99-us")
			}
		})
	}
}
