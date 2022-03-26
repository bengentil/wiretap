// SPDX-License-Identifier: GPL-3.0
// Copyright (c) 2022 Benjamin Gentil

package wiretap

type TapEvent interface {
	Pid() uint32
	Comm() string
	Probe() TapProbe
	Data() []byte
}
