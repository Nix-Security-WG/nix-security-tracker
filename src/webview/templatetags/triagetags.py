from typing import Any

from django import template

register = template.Library()


@register.filter
def clean_nones(input: list[Any]) -> list[Any]:
    return [e for e in input if e is not None]


@register.filter
def default_to_na(input: Any) -> Any:
    if input == "n/a" or input == "" or input is None:
        return "N/A"
    return input


@register.filter
def index(input: list[Any], index: int) -> Any:
    return input[index]
