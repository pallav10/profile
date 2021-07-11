from django.conf.urls import include, url
from rest_framework.routers import DefaultRouter

from views import UserRegistrationAPIView, UserLoginAPIView, UserLogoutAPIView

urlpatterns = [
    url(r"^register/$", UserRegistrationAPIView.as_view(), name="register"),
    url(r"^login/$", UserLoginAPIView.as_view(), name="login"),
    url(r"^logout/$", UserLogoutAPIView.as_view(), name="logout"),
]
