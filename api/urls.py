from django.conf.urls import include, url
from rest_framework.authtoken.views import obtain_auth_token

from api.views import (
    UserRegistrationAPIView,
    UserLoginAPIView,
    UserLogoutAPIView,
    UserProfileView,
)

urlpatterns = [
    url(r"^register/$", UserRegistrationAPIView.as_view(), name="register"),
    url(r"^login/$", UserLoginAPIView.as_view(), name="login"),
    url(r"^logout/$", UserLogoutAPIView.as_view(), name="logout"),
    url(r"profile/", UserProfileView.as_view(), name="profile",),
    url(r"api-token-auth/", obtain_auth_token, name="api_token_auth"),
]
