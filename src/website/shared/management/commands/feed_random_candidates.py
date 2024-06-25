import argparse
import logging
from typing import Any

import pandas as pd
from django.core.management.base import BaseCommand
from django.db.models import F
from django_pandas.io import read_frame
from recordlinkage import Index
from shared.models import Container, LinkageCandidate, NixDerivation

logger = logging.getLogger(__name__)


def get_daframes() -> Any:
    """
    Return dataframes from the appropriate querysets.
    """
    container_qs = (
        Container.objects.select_related("descriptions", "affected", "cve")
        .exclude(title="")
        .order_by("id", "-date_public")
        .annotate(container_id=F("id"))
        .values(
            "container_id",
            "title",
            "descriptions__value",
            "affected__vendor",
            "affected__product",
            "affected__package_name",
            "affected__repo",
            "affected__cpes__name",
        )
    )

    pkg_qs = (
        NixDerivation.objects.select_related("metadata")
        .order_by("id")
        .annotate(derivation_id=F("id"))
        .values(
            "derivation_id",
            "attribute",
            "name",
            "system",
            "metadata__name",
            "metadata__description",
        )
    )

    return read_frame(container_qs.all()[:4]), read_frame(pkg_qs)


def provide_candidates(df_a: Any, df_b: Any) -> Any:
    indexer = Index().random(n=200)
    candidate_links = indexer.index(df_a, df_b)

    return candidate_links


class Command(BaseCommand):
    """
    Generate and insert random record linkage candidates.

    By providing random record linkage candidates we can quickly:
      - validate the triage candidates workflow
      - bootstrap supervised training for linkage classification models.
    """

    help = "Generate and insert random record linkage candidates."

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        pass

    def handle(self, *args: str, **kwargs: Any) -> None:  # pyright: ignore reportUnusedVariable
        logger.info(
            "Resetting group permissions based on their Github team memberships."
        )

        container_df, pkg_df = get_daframes()
        container_ids = container_df.loc[:, "container_id"]
        pkg_ids = pkg_df.loc[:, "derivation_id"]

        print("\nExample row for container DF:")
        print(container_df.iloc[0])

        print("\nExample row for pkg DF:")
        print(pkg_df.iloc[0])

        # Candidates are return as a MultiIndex
        candidates = provide_candidates(container_df, pkg_df)
        print()
        print(candidates)

        # Extract each ID pairs from their respective side of the MultiIndex
        candidate_container_ids = (
            container_ids.loc[candidates.get_level_values(0)]
        ).reset_index(drop=True)
        candidate_pkg_ids = (pkg_ids.loc[candidates.get_level_values(1)]).reset_index(
            drop=True
        )
        id_pairs = pd.concat([candidate_container_ids, candidate_pkg_ids], axis=1)

        print("\nCandidates to insert:")
        print(id_pairs)

        # Insert the candidates in bulk
        logger.info("Preparing candidates to insert.")
        data = id_pairs.to_dict(orient="records")
        instances = [LinkageCandidate(**row) for row in data]
        LinkageCandidate.objects.bulk_create(instances)
        logger.info("%s candidates inserted.", len(instances))
