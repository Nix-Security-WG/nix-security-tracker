from argparse import ArgumentParser
from typing import Any

from django.core.management.base import BaseCommand

from shared.models import NixEvaluation


class Command(BaseCommand):
    help = "Transition all in-progress evaluations to the crashed state"

    def add_arguments(self, parser: ArgumentParser) -> None:
        pass

    def handle(self, *args: Any, **kwargs: Any) -> str | None:
        crashed = NixEvaluation.objects.filter(
            state=NixEvaluation.EvaluationState.IN_PROGRESS
        ).update(state=NixEvaluation.EvaluationState.CRASHED)
        print(
            f"{crashed} evaluations were transitioned to a crash state as a leftover of the previous worker"
        )
