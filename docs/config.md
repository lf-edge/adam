# Configuration Files

According to [the API](http://github.com/lf-edge/eve/blob/master/api/API.md) and the [EVE implementation](http://github.com/lf-edge/eve), once a device is registered, it will ask for its config with some regularity.

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
