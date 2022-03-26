// SPDX-License-Identifier: GPL-3.0
// Copyright (c) 2022 Benjamin Gentil

package output

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/bengentil/wiretap/pkg/wiretap"
)

type Stdout struct{}

func (o Stdout) Name() string {
	return "stdout"
}

func (o Stdout) Print(e wiretap.TapEvent) {
	log.Printf("[%s] returned in %s(%d), len=%d", wiretap.ProbeName(e.Probe()), e.Comm(), e.Pid(), len(e.Data()))
	fmt.Printf("%s", hex.Dump(e.Data()))
}
