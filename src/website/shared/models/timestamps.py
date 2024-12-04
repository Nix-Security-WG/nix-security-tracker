"""Timestamp mixins
Collection of timestamp mixins to be used for standard behaviours when we need to add
timestamps to models.

Check the Django documentation for the default behaviour of the `auto_now` and `auto_now_add` options.

Check the following resource for a good summary and examples of how to combine them to achieve
different timestamp behaviours:
    - https://www.hacksoft.io/blog/timestamps-in-django-exploring-auto-now-auto-now-add-and-default
"""

from django.db import models


class TimeStampWithWritableUpdatedAtMixin(models.Model):
    """Timestamp mixin where `updated_at` is nullable and writable.
    Having `updated_at` being NULL at insertion allows, for example, for an easy
    check to display creation time vs update time when rendering activity logs.
    """

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:  # type: ignore[override]
        abstract = True
