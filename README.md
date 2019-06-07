# Adam

Welcome to Adam! Adam is the reference implementation of an [LF-Edge](https://www.lfedge.org) [API-compliant Controller](https://github.com/lf-edge/eve/blob/master/api/API.md). You can use Adam to drive one or more [EVE](https://www.lfedge.org/projects/eve/) instances from any computer, locally, in the cloud, or in a container.

Adam is a reference implementation. Thus, while it has all of the TLS encryption and authentication requirements of [the official API](https://github.com/lf-edge/eve/blob/master/api/API.md), it has not been built or tested to withstand penetration attacks, DDoS, or any other major security requirements, and it has not been built with massive scale in mind. For those, please refer to various vendor cloud controller offerings, such as [Zededa zedcloud](https://www.zededa.com/technology/).

## Running Adam

To run Adam, you need a built Adam binary. Adam distributes both as a single binary available on all major platforms - Linux, macOS, Windows - as well as an OCI compliant container image.

The `adam` command has multiple options. The primary one is:

```
adam server
```

which will run Adam, listening on the default port of `8080` (it will tell you which when it starts), using the default server TLS key and certificate, using `./run/adam/` as its file storage location. These options are modifiable via the command-line; run `adam server --help` for options.

If you prefer to run Adam as a docker container:

```
docker run zededa/adam server
```

You can add any of the options that would exist with a local Adam installation, including help: `docker run zededa/adam server --help`.

Note that when running in a docker container, directories are ephemeral. If you want to keep the directories, you should bind-mount them into your container. To make things easier, this repository includes a sample `docker-compose.yml` which runs adam, maps port `8080` in the container to `8080` on your host, and mounts the current directory's `./run/adam/` to the default `/adam/run/adam/` in the container.

## Building Adam

Building Adam is straightforward:

1. Clone this repo
2. Ensure you have installed either go >= 1.11, or docker
3. Run `make build-docker` to build in docker (or just `make build` or even `make`), or `make build-local` to build using a local installation of go

This will build `adam` for your local operating system and architecture.

All `Makefile` commands have the option to run locally or in docker. By default, they run in docker. If you prefer to run using a locally installed go, pass `BUILD=local` to any command, e.g.

```
make vet BUILD=local
```

## Server TLS

Adam _requires_ TLS to communicate with EVE devices, which means a server key and certificate. If one is not available, it will fail startup. You can generate one using:

```
adam generate server
```

Run `adam generate server --help` for options. By default, it stores the server key and certificate in the same location as the default when running `adam server`.

## Registering Devices

For an EVE device to be accepted into Adam, it needs to be listed as one of:

* acceptable to onboard
* registered

### Onboarding

Onboarding is the process of enabling a device to self-register. This requires two pieces: an onboarding certificate, and a unique serial string. Each self-registering device _must_ have a unique combination of onboarding certificate and serial string.

Adam has an onboarding directory where it maintains acceptable onboarding certificates and serials. By default, these are under `./run/adam/onboard/<cn>/`, where the name _cn_ is a file-friendly conversion of the certificate's Common Name. This directory contains two files:

* `cert.pem` - the actual onboarding certificate.
* `serials.txt` - a list of acceptable serials to use with this certificate, one per line. The wildcard `*` means _any_ serial will be accepted.

You _can_ modify these files directly; it is not, however, recommended. 

Instead, use Adam's command-line `admin` options to work with the files:

```
adam generate
```

will generate a key/certificate pair, with a Common Name that you provide. Run `adam generate --help` for options.

You then can interact with the Adam server using `adam admin`:

```
$ adam admin device
$ adam admin onboard
```

These will list, add, remove, get or clear onboarding certificates and their serials, as well as devices directly.

Once you have generated an onboarding certificate, copy the certificate and key to the device to onboard.

## More Documentation

More documentation is available in the [docs/](./docs) directory.

