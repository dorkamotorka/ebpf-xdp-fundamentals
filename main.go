package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf xdp xdp.c

import (
	"fmt"
	"log"
	"net"
	"flag"
	"os"
	"context"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	var ifname string
	flag.StringVar(&ifname, "i", "lo", "Network interface name where the eBPF programs will be attached")
	flag.Parse()

	// Signal handling / context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs xdpObjects
	if err := loadXdpObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach XDP program to the network interface.
	xdplink, err := link.AttachXDP(link.XDPOptions{
				Program:   objs.XdpProgram,
				Interface: iface.Index,
				Flags: link.XDPGenericMode,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer xdplink.Close()
	fmt.Println("XDP program successfully attached. Press Enter to exit.")

	// Wait for SIGINT/SIGTERM (Ctrl+C) before exiting
	<-ctx.Done()
	log.Println("Received signal, exiting...")
}
