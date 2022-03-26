// SPDX-License-Identifier: GPL-3.0
// Copyright (c) 2022 Benjamin Gentil

package wiretap

type TapEventOutput interface {
	Name() string
	Print(event TapEvent)
}
