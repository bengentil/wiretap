// SPDX-License-Identifier: GPL-3.0
// Copyright (c) 2022 Benjamin Gentil

package wiretap

type TapProbe interface {
	Name() string
	Symbol() string
	Executable() string
	Start(eventChannel chan<- TapEvent, stopChannel <-chan bool) error
}

func ProbeName(p TapProbe) string {
	return p.Name() + ":" + p.Symbol() + ":" + p.Executable()
}
