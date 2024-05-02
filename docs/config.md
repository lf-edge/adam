# Configuration Files

According to [the API](https://github.com/lf-edge/eve-api/blob/main/APIv2.md) and the [EVE implementation](http://github.com/lf-edge/eve), once a device is registered, it will ask for its config with some regularity.

Adam does _not_ require pre-registration or pre-configuration of devices. You _can_ pre-register devices by installing the device certificate, or you can activate a device by installing an onboarding certificate and the serial number for the device (or a wildcard).

When Adam receives its first request for a configuration for a registered device, it is likely to find no configuration present. It will generate an empty one containing just the UUID. 

You can request the current config using 

```
adam admin device config get --uuid <UUID>
```

It will return the config as a JSON string. Save the JSON to a file, modify it by editing that file, and then update it using:

```
adam admin device config set --uuid <UUID> --config-path <path-to-file>
```

`admin config set` supports reading from stdin using the path of `-`, so you can use the following process:

1. Get a list of devices

```
adam admin device list
```

1. Get the config for an individual device and save to a file

```
adam admin device config get --uuid 1234567 > config.json
```

1. Edit the json as you wish
1. Save the new config

```
adam admin device config set --uuid 1234567 --config-path config.json
# OR
cat config.json | adam admin device config set --uuid 1234567
```

