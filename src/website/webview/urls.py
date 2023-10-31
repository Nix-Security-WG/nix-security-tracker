from django.urls import path

from webview.views import HomeView

app_name = "webview"
urlpatterns = [
    path("", HomeView.as_view(), name="home"),
]
