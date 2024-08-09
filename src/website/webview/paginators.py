from typing import Any

from django.core.paginator import Paginator
from django.utils.functional import cached_property


class CustomCountPaginator(Paginator):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.custom_count = kwargs.pop("custom_count")
        super().__init__(*args, **kwargs)

    @cached_property
    def count(self) -> int:
        return self.custom_count()
