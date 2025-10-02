package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf drop_process.c

func main() {
	port := flag.Int("port", 4040, "TCP port to allow for the process")
	processName := flag.String("process", "myprocess", "Process name to filter")
	cgroupPath := flag.String("cgroup", "/sys/fs/cgroup", "Cgroup path to attach to")
	flag.Parse()

	if len(*processName) > 15 {
		log.Fatal("Process name must be 15 characters or less")
	}

	// Load eBPF program
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Loading eBPF objects: %v", err)
	}
	defer objs.Close()

	// Configure the process name and allowed port
	key := uint32(0)
	cfg := bpfConfig{
		AllowedPort: uint16(*port),
	}

	// Convert string to [16]int8 array
	for i := 0; i < len(*processName) && i < 16; i++ {
		cfg.ProcessName[i] = int8((*processName)[i])
	}

	if err := objs.ConfigMap.Put(&key, &cfg); err != nil {
		log.Fatalf("Failed to update config map: %v", err)
	}

	// Attach cgroup programs
	linkSockCreate, err := link.AttachCgroup(link.CgroupOptions{
		Path:    *cgroupPath,
		Attach:  ebpf.AttachCGroupInetSockCreate,
		Program: objs.TrackProcess,
	})
	if err != nil {
		log.Fatalf("Failed to attach sock_create program: %v", err)
	}
	defer linkSockCreate.Close()

	linkConnect, err := link.AttachCgroup(link.CgroupOptions{
		Path:    *cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.FilterConnect,
	})
	if err != nil {
		log.Fatalf("Failed to attach connect4 program: %v", err)
	}
	defer linkConnect.Close()

	fmt.Printf("✓ eBPF program attached to cgroup: %s\n", *cgroupPath)
	fmt.Printf("✓ Filtering process: %s\n", *processName)
	fmt.Printf("✓ Allowing only port %d, dropping all other ports\n", *port)
	fmt.Println("Press Ctrl+C to exit...")

	// Wait for signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	fmt.Println("\nDetaching eBPF program...")
}
