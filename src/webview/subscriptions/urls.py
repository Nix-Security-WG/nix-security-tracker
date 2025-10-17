from django.urls import path

from .views import (
    AddSubscriptionView,
    RemoveSubscriptionView,
    SubscriptionCenterView,
)

app_name = "subscriptions"

urlpatterns = [
    path("", SubscriptionCenterView.as_view(), name="center"),
    path("add/", AddSubscriptionView.as_view(), name="add"),
    path("remove/", RemoveSubscriptionView.as_view(), name="remove"),
]
