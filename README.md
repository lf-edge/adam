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
docker run lfedge/adam server
```

You can add any of the options that would exist with a local Adam installation, including help: `docker run lfedge/adam server --help`.

Note that when running in a docker container, directories are ephemeral. If you want to keep the directories, you should bind-mount them into your container.

```
docker run -v $PWD/run:/somedir/run lfedge/adam server --conf-dir /somedir/run/config --db-url /somedir/run/adam --server-cert /somedir/run/adam/server.pem --server-key /somedir/run/server-key.pem
```

The default working directory for `adam` in the container is `/adam/`, which means the following will just work:

```
docker run -v $PWD/run:/adam/run lfedge/adam server
```

Or, you can use volume containers.

To make things easier, this repository includes a sample `docker-compose.yml` which runs adam, maps port `8080` in the container to `8080` on your host, and mounts the current directory's `./run/adam/` to the default `/adam/run/adam/` in the container.

Finally, remember to map your ports when using a docker container:

```
docker run -v $PWD/run:/adam/run -p 8080:8080 lfedge/adam server
```

By default, `adam` listens on port `8080`, but can be configured. Run `adam server --help`.

Finally, you can embed Adam container into an EVE root filesystem creating an EVE instance that can be controlled externally by clients talking to Adam and Adam relaying it to EVE. This comes very handy in testing and any other situation where turning EVE's configuration pull model into a push one makes sense. Note that this deployment mode forever commits a single Adam instance to a single EVE instance and all the communication between EVE and Adam happen via localhost on the running EVE edge node. Adam container has a script [eve-embedded.sh](scripts/eve-embedded.sh) that orchestrates this bond and the Adam container can be used to build EVE image via the following stanza in EVE's image YAML file:

```
   - name: adam
     image: lfedge/adam:latest
     binds:
        - /var/persist:/persist
        - /var/config:/config
     command: ["/bin/eve-embedded.sh"]
     net: host
```

## Building Adam

Building Adam is straightforward:

1. Clone this repo
2. Ensure you have installed either go >= 1.11, or docker
3. Build

There are several options for building:

* `make image` will run the entire build in a docker container and give you a docker image. No local binaries will be created.
* `make build` will create the binary `bin/adam-<os>-<arch>` for your OS and architecture. You can override either by `make OS=<os>` and/or `make ARCH=<arch>`, e.g. `make OS=linux ARCH=arm64`. The build itself will happen with in a docker image or using your locally installed `go`; see below.
* `make image-local` will take the locally built binary and create an image with it.

These options allow you to do a one-step image build with no dependencies (`make image`), build a binary for your local usage (`make build`) using either your locally installed go or in a docker container, and make an image that uses your local binary (`make image-local`). The latter is often for quick reproducible builds.

All `Makefile` commands that execute `go` have the option to run locally or in docker. By default, they run in docker. If you prefer to run using a locally installed go, pass `BUILD=local` to any command, e.g.

```
make vet BUILD=local
make build BUILD=local
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

An EVE device has to know the following before it can communicate with any controller (including Adam):

* controller's host name and port #
* controller's root certificate

additionally you may need to supply an entry mapping controller's host name to a routable IP address (in the /etc/hosts format)

When Adam server runs, it outputs all the required configuration in a folder specified by the `conf-dir` option (run/adam/config by default)

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

