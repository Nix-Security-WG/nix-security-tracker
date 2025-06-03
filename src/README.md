# Architecture

The Nix Security Tracker is implemented in the Django framework.

In addition to the `manage.py` administration utility, there are three top-level directories here:

- [`project`](./project/): Configuration for the web server running the project.
- [`shared`](./shared/): Utilities and models consumed by the other components.
- [`webview`](./webview/): The views which comprise the web frontend.
