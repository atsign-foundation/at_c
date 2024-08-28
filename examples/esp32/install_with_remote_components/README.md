# install_with_remote_components

## Who Is This For?

This is the recommended way of installing our components in your ESP-IDF projects.

If you want a quick and easy way to use our components in your Espressif projects, you are in the right place.

## How To Install With Remote Components

Our components can be found under the atsign-foundation namespace on the [component registry](<!-- TODO -->).

1. In your the root directory of your ESP-IDF project, run the following:

```bash
idf.py add-dependency "atsign-foundation/atclient^0.1.0"
```

This should have made an `idf_component.yml` in your `main/` component (if it didn't exist already) and added `atsign-foundation/atclient: "^0.1.0"` to the dependencies list

2. Build

```
idf.py build
```

Running this successfully should have created a `managed_components/` directory with `atchops`, `atclient`, `atlogger`, and `uuid4` as directories within that directory.

3. Code

You are ready to begin coding.

In your `main.c`, add `#include <atclient/atclient.h>` and rebuild and that should work just fine.
