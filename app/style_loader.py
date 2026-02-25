# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2023 Kagati Foundation <https://kagatifoundation.github.org>

import os

def get_style(file_name: str) -> str:
    """Safely loads a QSS/CSS file from the local directory."""
    base_path = os.path.dirname(__file__)
    file_path = os.path.join(base_path, file_name)
    
    try:
        with open(file_path, "r") as f:
            return f.read()
    except FileNotFoundError:
        print(f"Warning: Style file {file_name} not found.")
        return ""