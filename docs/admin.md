# Admin

There are two ways to administer an adam instance:

* The admin API
* The `adam admin` command

In truth, the `adam admin` command is just a wrapper to the admin API, to ease usage.

## Endpoints

The following are the admin endpoints:

* `GET /onboard` - list all onboard certificates
* `GET /onboard/{cn}` - get a specific onboard certificate
* `POST /onboard` - upload a new onboarding certificate
* `DELETE /onboard` - clear all onboarding certificates
* `DELETE /onboard/{cn}` - delete a specific onboarding certificate
* `GET /device` - list all devices
* `GET /device/{uuid}` - get details of one device
* `GET /device/{uuid}/config` - get config for one device
* `PUT /device/{uuid}/config` - update config for one device
* `GET /device/{uuid}/logs` - get all known logs for one device; set header `X-Stream=true` to stream all new logs instead
* `GET /device/{uuid}/info` - get all known info messages for one device; set header `X-Stream=true` to stream all new info instead
* `POST /device` - create a new device
* `DELETE /device` - delete all devices
* `DELETE /device/{uuid}` - delete one specific device
