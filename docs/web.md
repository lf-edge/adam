# Web

Adam includes a Web server for control of the system, including devices under management.

All of the static pages are in this repository under [web/static](../web/static).

You can access all pages from the root URL via https://server:port/static/page

In addition, the page [static/index.html](../web/static/index.html) is accessible at the
root of the Web server at https://server:port/ and https://server:port/index.html

At build time, everything in [web/static](../web/static) is embedded into the Adam binary,
enabling it to be distributed as a single file. For development purposes, you can choose to serve
files from the filesystem by passing it the `--web-dir <directory>` option, for example:

```
adam server --web-dir ./web/static
```

The passed `<directory>` must be the root of the static files. Do not start above the `static/`
path.

```
adam server --web-dir ./web/static    # CORRECT
adam server --web-dir ./web           # INCORRECT
```
