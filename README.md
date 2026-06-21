# HexParticle - Packet Analyzer (Unpacking Networks, One Packet at a Time)

It looks like this right now on Linux:
![Screenshot](https://i.imgur.com/McX5jND.png)

This is a Python-based GUI application that utilizes the internal `netdsl` library for core processing.

## Getting Started

Follow these steps to set up the application and link the required library.

### 1. Prerequisites
Make sure you have Python 3.13+ installed.

### 2. Clone/Download the Projects
Ensure both the GUI app and the library folders are on your machine, ideally side-by-side:
```text
development/
├── netdsl/          # The NetDSL compiler
└── HexParticle/     # This HexParticle app
```

### 3. Build NetDSL
Go to NetDSL and follow the instructions under ```Using NetDSL as a library``` section in its README file.

### 4. Install NetDSL
```shell
$ python3 -m pip install ./path/to/netdsl
```