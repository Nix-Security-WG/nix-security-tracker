from django.core.management.base import BaseCommand
from shared.models.nix_evaluation import NixChannel


class Command(BaseCommand):
    help = "Register Nix channels"

    def add_arguments(self, parser):
        parser.add_argument("staging_branch", type=str)
        parser.add_argument("channel_branch", type=str)
        parser.add_argument("state", type=str)

    def handle(self, *args, **kwargs):
        kwargs["repository"] = "https://github.com/NixOS/nixpkgs"
        params = {
            "repository": "https://github.com/NixOS/nixpkgs",
            "staging_branch": kwargs["staging_branch"],
            "channel_branch": kwargs["channel_branch"],
            "state": kwargs["state"],
        }
        NixChannel.objects.get_or_create(**params)
