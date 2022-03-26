// SPDX-License-Identifier: GPL-3.0
// Copyright (c) 2022 Benjamin Gentil

package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"

	"github.com/bengentil/wiretap/pkg/output"
	"github.com/bengentil/wiretap/pkg/probe/openssl"
	"github.com/bengentil/wiretap/pkg/wiretap"
	"github.com/cilium/ebpf/rlimit"
)

func eventLoop(eventChannel <-chan wiretap.TapEvent, stopChannel <-chan bool, output wiretap.TapEventOutput) {
eventLoop:
	for {
		select {
		case event := <-eventChannel:
			output.Print(event)
		case <-stopChannel:
			break eventLoop
		}
	}
}

func main() {
	var out wiretap.TapEventOutput
	var probes []wiretap.TapProbe
	var stopChannels []chan bool
	wg := sync.WaitGroup{}
	eventChannel := make(chan wiretap.TapEvent)

	fOutput := flag.String("o", "stdout", "output (stdout, pcap, http-files)")
	flag.Parse()

	switch *fOutput {
	case "stdout":
		out = &output.Stdout{}
	default:
		log.Fatalf("unexpected output: %s", *fOutput)
	}

	if len(flag.Args()) > 0 {
		for _, arg := range flag.Args() {
			s := strings.Split(arg, ":")
			if len(s) != 3 {
				log.Fatalf("expected <probe>:<symbol>:<file>, got: %s", arg)
			}

			probe, symbol, file := s[0], s[1], s[2]
			switch probe {
			case "openssl":
				probes = append(probes,
					openssl.NewProbe(symbol, file),
				)
			default:
				log.Fatalf("unexpected probe: %s", probe)
			}
		}
	} else {
		log.Println("Using default probes...")
		probes = append(probes,
			openssl.NewProbe("SSL_read", "/lib64/libssl.so"),
			openssl.NewProbe("SSL_write", "/lib64/libssl.so"),
		)
	}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Start each probe in a goroutine
	for _, p := range probes {
		p := p
		stopChannel := make(chan bool)
		stopChannels = append(stopChannels, stopChannel)
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := p.Start(eventChannel, stopChannel)
			if err != nil {
				log.Printf("[%s] probe failed: %s", wiretap.ProbeName(p), err)
				<-stopChannel
			} else {
				log.Printf("[%s] probe stopped successfully", wiretap.ProbeName(p))
			}
		}()
	}

	// Start the main loop that will receive all events from probes
	stopChannel := make(chan bool)
	stopChannels = append(stopChannels, stopChannel)
	wg.Add(1)
	go func() {
		defer wg.Done()
		eventLoop(eventChannel, stopChannel, out)
	}()

	// Wait for a SIGINT signal, then stop all goroutine gracefully
	interruptChannel := make(chan os.Signal, 1)
	signal.Notify(interruptChannel, os.Interrupt)

	for range interruptChannel {
		log.Println("Stopping gracefully...")
		for _, c := range stopChannels {
			c <- true
		}
		break
	}
	wg.Wait()
}
