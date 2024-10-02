# Architecture

The Nix Security Tracker is implemented in the Django framework.

In addition to the `manage.py` administration utility, there are three top-level directories here:

- [`shared`](./shared/): Utilities and models consumed by the other components.
- [`tracker`](./tracker/): Definitions for the web server which presents the service.
- [`webview`](./webview/): The views which comprise the web frontend.
