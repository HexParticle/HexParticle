# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import typing

from hexlib.lib_wrapper import HexParticleLib

class AppContext:
    def __init__(self, cmd_options: typing.Dict[str, typing.Any]):
        self.cmdline_options: typing.Dict[str, typing.Any] = cmd_options
        self._lib = HexParticleLib(self.cmdline_options.lib_path)