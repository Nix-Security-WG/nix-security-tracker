from collections.abc import Callable
from typing import Any

from django.core.paginator import Paginator
from django.utils.functional import cached_property


class CustomCountPaginator(Paginator):
    """
    We want to use a custom count function, since due to grouping and aggregation
    the defaults will produce redundant, expensive queries.
    """

    def __init__(
        self, *args: Any, custom_count: Callable[[], int], **kwargs: Any
    ) -> None:
        self.custom_count = custom_count
        super().__init__(*args, **kwargs)

    @cached_property
    def count(self) -> int:  # type: ignore[override]
        return self.custom_count()

class LargeTablePaginator(Paginator):
    """
    Overrides the count method to get an estimate instead of actual count when not filtered
    """

    _count = None

    @property
    def count(self) -> int:
        """
        Changed to use an estimate if the estimate is greater than 10,000
        Returns the total number of objects, across all pages.
        """
        if self._count is None:
            self._count = self.object_list.model.objects.count()

        return self._count
