from django.urls import include, path
from rest_framework import routers

from shared.views import NixpkgsIssueViewSet

v1_router = routers.DefaultRouter()
v1_router.register(r"issues", NixpkgsIssueViewSet)

urlpatterns = [
    path("v1/", include(v1_router.urls)),
]
