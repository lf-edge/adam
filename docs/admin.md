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
* `GET /device/{uuid}/options` - set options for one device
* `PUT /device/{uuid}/options` - update options for one device
* `GET /options` - set global options
* `PUT /options` - update global options
* `POST /certs` - update signing certificate

## Adam Admin

The `adam admin` command allows you to speak directly to a running `adam` device using the CLI.
It has several subcommands for managing onboarding certificates, devices, etc. Run `adam admin --help`
to see your options.

There are several options for all `adam admin` commands, primarily:

* the URL to the adam server to use
* the path to the CA certificate for validating the adam server's TLS certificate
* whether or not to trust expired or unsigned certificates

Run `adam admin --help` to see the options. All three of these also can read environment variables,
to avoid your needing to specify common options every time. They also have reasonable defaults.
`adam admin --help` will tell you the options, the environment variables and the defaults.

In all cases, CLI flag overrides environment variable overrides the default.

For example, the default server URL is `https://localhost:8080`. If nothing else is specified,
it will use that URL. If you specify `ADAM_SERVER=https://lfedge.org:5000`, it will use that,
as environment variable overrides the default.

Similarly, if you specify `adam admin --server=https://foo.com:4000`, it will use that,
as CLI flag overrides the default. Finally, if you specify:

```console
ADAM_SERVER=https://lfedge.org:5000 adam admin --server=https://foo.com:4000
```

It will use the CLI flag option, `https://foo.com:4000`, as CLI flag overrides environment
variable, which overrides the default.
