# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation

import typing

from hexlib.lib_wrapper import HexParticleLib

class AppContext:
    def __init__(
        self,
        cmd_options: typing.Dict[str, typing.Any]
    ):
        self.cmdline_options: typing.Dict[str, typing.Any] = cmd_options
        
        self._lib = HexParticleLib(lib_path=self.cmdline_options.lib_path)


    def initialize_library(self, source: str, mode: int):
        if source is None or mode is None:
            print("Capture mode or capture source is undefined.")
            return

        self.capture_source = source
        self.capture_mode = mode
        
        if self._lib is not None:
            self._lib.initialize_hexp_instance(source, mode)