# Cloud9 (C++)
[![Build Status](https://travis-ci.org/avevad/cloud9-cpp.svg?branch=master)](https://travis-ci.org/avevad/cloud9-cpp)

### About
Cloud9 is a self-hosted cloud storage for your server.

**Note:** C++ part of the cloud is linux-only (cross-platform GUI client is coming soon).

### Getting it
There are two variants of getting the cloud:
1. Download ready-to-use binaries from [releases](http://github.com/avevad/cloud9-cpp/releases) page.
2. Clone the repo and build the cloud on your own.

### Building
If you want to build the cloud yourself, follow these instructions.
```shell script
git clone https://github.com/avevad/cloud9-cpp
cd cloud9-cpp
cd cmake-build-release
cmake -DCMAKE_BUILD_TYPE=Release ..
make all
make test
```

### Overview & installing
After building (or downloading) the cloud you will get two binaries:
1. `cloud9d` - cloud server
1. `cloud9` - CLI cloud client

If you build the binaries on your own, you can install them:
`make install`
If you download the binaries from releases page, you should manually copy them to the system's binaries location.

### Using CLI
Execute `cloud9 -h` to get CLI usage help.
When in the shell, type `help` to get list of available commands.

### Setting up server
Firstly, you need to setup the server's workspace and create a config file for the server.
An example of server's workspace and can be found in `sample_server` directory of repo's tree.
The server's workspace should contain server configuration file (`config.lua`).
The guide through the configuration options is located at the example server's configuration file.
After the workspace setup you can `cd` into the server's workspace and start the server with `cloud9d` command.
