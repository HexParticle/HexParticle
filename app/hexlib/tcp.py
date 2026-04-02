# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

FLAG_MEANING = {
	1: 		"FIN",
	2: 		"SYN",
	4: 		"RST",
	8: 		"PSH",
	16: 	"ACK",
	32: 	"URG",
	64: 	"ECE",
	128: 	"CWR"
}

TCP_OPTION_NOP = 				0x1
TCP_OPTION_MSS = 				0x2
TCP_OPTION_WINDOW_SCALE = 		0x3
TCP_OPTION_SACK_PERMITTED = 	0x4
TCP_OPTION_SACK = 				0x5
TCP_OPTION_TIMESTAMPS = 		0x8
TCP_OPTION_UTO = 				0x1C
TCP_OPTION_AUTH = 				0x1D
TCP_OPTION_MPTCP = 				0x1E