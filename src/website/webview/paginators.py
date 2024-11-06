import json
from collections.abc import Callable
from typing import Any

from django.core.paginator import Paginator
from django.db.models import QuerySet
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
    Return an estimate for large numbers
    """

    @property
    def count(self) -> int:
        if not isinstance(self.object_list, QuerySet):
            return len(self.object_list)

        plan = self.object_list.explain(format="json")
        try:
            estimate = json.loads(plan)[0]["Plan"]["Plan Rows"]
            if estimate > 1000:
                return estimate
        except (KeyError, IndexError, TypeError):
            pass

        return self.object_list.count()
