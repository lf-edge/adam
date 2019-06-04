# Directory Structure

When running Adam using its `file` driver, all data about devices and onboarding are stored in a directory root, by default `./run/adam/`. Under this directory is the following structure:

```
-run
  |-- adam
        |-- device/
              |-- <uuid>/
              |-- <uuid>/
              |-- <uuid>/
        |-- onboard/
              |-- <cn>/
              |-- <cn>/
        |-- server.pem
        |-- server-key.pem
```

## Devices

Each directory in `device/` represents a unique registered device, with the directory named for the UUID generated when the device was registered. The structure of each device directory is as follows:

```
 - <uuid>
    |-- config.json
    |-- onboard-certificate.pem
    |-- device-certificate.pem
    |-- serial.txt
    |-- logs/
          |-- <timestamp>
          |-- <timestamp>
          |-- <timestamp>
    |-- metrics/
          |-- <timestamp>
          |-- <timestamp>
          |-- <timestamp>
    |-- info/
          |-- <timestamp>
          |-- <timestamp>
          |-- <timestamp>
```

The purpose of each file and directory is as follows:

* `config.json` - configuration of format `config.EdgeDevConfig` from [the API](https://github.com/lf-edge/eve/blob/master/api/API.md), marshalled to json.
* `onboard-certificate.pem` - the onboard certificate used when this device self-registered. If the device was registered directly, this file will not exist.
* `device-certificate.pem` - the device certificate for this device.
* `serial.txt` - the serial used when this device self-registered. If the device was registered directly, this file will not exist.
* `logs/` - directory with all of the log messages sent by the device. One file per message, named by the timestamp. The message is marshalled from protobuf to json.
* `metrics/` - directory with all of the metrics messages sent by the device. One file per message, named by the timestamp. The message is marshalled from protobuf to json.
* `info/` - directory with all of the info messages sent by the device. One file per message, named by the timestamp. The message is marshalled from protobuf to json.

## Onboard

Each directory in `onboard/` represents a unique onboarding certificate and the serials permitted to that onboarding certificate, with the directory named for the CN of the certificate. The CN is converted to be directory-name=friendly. The structure of each onboard directory is as follows:

```
 - <cn>
    |-- cert.pem
    |-- serials.txt
```

The purpose of each file and directory is as follows:

* `cert.pem` - the onboarding certificate.
* `serials.txt` - a list of valid serials for use with this onboarding certificate, one per line. The wildcard `*` means to allow any serial to register with this certificate.


