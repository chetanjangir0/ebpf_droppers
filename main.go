package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf drop_tcp.c

func main() {
	port := flag.Int("port", 4040, "TCP port to drop packets on")
	iface := flag.String("interface", "lo", "Network interface to attach to")
	flag.Parse()

	// Load eBPF program
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Loading eBPF objects: %v", err)
	}
	defer objs.Close()

	// Configure the port in the map
	key := uint32(0)
	portValue := uint16(*port)
	if err := objs.PortMap.Put(&key, &portValue); err != nil {
		log.Fatalf("Failed to update port map: %v", err)
	}

	// Get network interface
	link, err := netlink.LinkByName(*iface)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", *iface, err)
	}

	// Attach to TC (traffic control)
	qdiscAttrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: qdiscAttrs,
		QdiscType:  "clsact",
	}

	// Add qdisc (ignore if already exists)
	netlink.QdiscAdd(qdisc)

	// Attach eBPF program using netlink filter
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    1,
			Protocol:  syscall.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           objs.DropTcpPort.FD(),
		Name:         "drop_tcp_port",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		log.Fatalf("Failed to attach eBPF program: %v", err)
	}
	defer netlink.FilterDel(filter)

	fmt.Printf("✓ eBPF program attached to %s\n", *iface)
	fmt.Printf("✓ Dropping TCP packets on port %d\n", *port)
	fmt.Println("Press Ctrl+C to exit...")

	// Wait for signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	fmt.Println("\nDetaching eBPF program...")
}
