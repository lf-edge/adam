# Configuration Files

According to [the API](http://github.com/lf-edge/eve/blob/master/api/API.md) and the [EVE implementation](http://github.com/lf-edge/eve), once a device is registered, it will ask for its config with some regularity.

Adam does _not_ require pre-registration or pre-configuration of devices. You _can_ pre-register devices by installing the device certificate, or you can activate a device by installing an onboarding certificate and the serial number for the device (or a wildcard).

When Adam receives its first request for a configuration for a registered device, it is likely to find no configuration present. It will generate an empty one containing just the UUID. 

You then can modify that configuration by editing the file, which will be sent to the device at the next request for `/config`.

The Adam file device manager stores the configuration as a json file `config.json` in the device-specific path. For example:

```
run/adam/device/<uuid>/config.json
```
