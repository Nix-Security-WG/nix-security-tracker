"""
Disable network calls in tests.

Functionality that requires a network call to be tested, will have to mock the request.
"""

from typing import Any

import httpretty
from django.test.runner import DiscoverRunner


class CustomTestRunner(DiscoverRunner):
    def run_tests(self, *args: Any, **kwargs: dict[str, Any]) -> Any:
        # ensure tests are isolated, this is important when running them in the development environment
        # this library may be overkill, replace it with something more lightweight if possible
        with httpretty.enabled(allow_net_connect=False):
            return super().run_tests(*args, **kwargs)
