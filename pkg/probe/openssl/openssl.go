// SPDX-License-Identifier: GPL-3.0
// Copyright (c) 2022 Benjamin Gentil

package openssl

import (
	"C"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/bengentil/wiretap/pkg/wiretap"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

// $BPF_CLANG and $BPF_CFLAGS are set in the Makefile
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS openssl bpf/openssl.bpf.c

type openSSLEvent struct {
	Pid  uint32
	Comm [32]uint8
	Len  uint32
	Type uint8
	Data [256]byte
}

type Event struct {
	event openSSLEvent
	probe wiretap.TapProbe
}

func (e Event) Pid() uint32 {
	return e.event.Pid
}

func (e Event) Comm() string {
	return unix.ByteSliceToString(e.event.Comm[:])
}

func (e Event) Probe() wiretap.TapProbe {
	return e.probe
}

func (e Event) Data() []byte {
	return e.event.Data[:e.event.Len]
}

type Probe struct {
	symbol     string
	executable string
}

func NewProbe(Symbol, Executable string) *Probe {
	return &Probe{symbol: Symbol, executable: Executable}
}

func (p Probe) Name() string {
	return "openssl"
}

func (p Probe) Symbol() string {
	return p.symbol
}

func (p Probe) Executable() string {
	return p.executable
}

func (p Probe) Start(eventChannel chan<- wiretap.TapEvent, stopChannel <-chan bool) error {

	// Load bpf objects and maps
	objs := opensslObjects{}
	if err := loadOpensslObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open executable containing the symbol to attach uprobe
	ex, err := link.OpenExecutable(p.executable)
	if err != nil {
		return fmt.Errorf("opening executable: %s", err)
	}

	// Attach program SSL_readwriteEnter to the symbol execution
	up, err := ex.Uprobe(p.symbol, objs.SSL_readwriteEnter, nil)
	if err != nil {
		return fmt.Errorf("opening kprobe: %s", err)
	}
	defer up.Close()

	// Attach program SSL_readwriteRet to the symbol return
	uretp, err := ex.Uretprobe(p.symbol, objs.SSL_readwriteRet, nil)
	if err != nil {
		return fmt.Errorf("opening kretprobe: %s", err)
	}
	defer uretp.Close()

	// Open a reader for perf events
	reader, err := perf.NewReader(objs.opensslMaps.Events, 64*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("NewReader: %s", err)
	}

	var sslEvent openSSLEvent
	var perfRecord = make(chan perf.Record)
	var perfError = make(chan error)

perfEventLoop:
	for {
		// Read events in a separate goroutine
		go func() {
			record, err := reader.Read()
			if err != nil {
				perfError <- err
			} else {
				perfRecord <- record
			}
		}()

		// Handle events
		select {
		case err := <-perfError:
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					// nothing to do, we're done
					return err
				}
				return fmt.Errorf("error reading perf ring buffer: %s", err)
			}
		case record := <-perfRecord:
			if record.LostSamples > 0 {
				return fmt.Errorf("lost %d samples", record.LostSamples)
			}
			// Parse the perf wiretap entry into a Event structure.
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &sslEvent); err != nil {
				return fmt.Errorf("parsing perf wiretap: %s", err)
			}

			if sslEvent.Type != 1 {
				return fmt.Errorf("unexpected wiretap type %d", sslEvent.Type)
			}

			eventChannel <- &Event{event: sslEvent, probe: p}
		case <-stopChannel:
			break perfEventLoop
		}
	}
	return nil
}
