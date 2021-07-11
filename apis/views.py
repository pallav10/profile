# -*- coding: utf-8 -*-
import utils
import validations_utils
from permissions import IsAuthenticated, UserPermissions

from rest_framework import schemas, status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import (
    api_view,
    permission_classes,
    renderer_classes,
)
from rest_framework.generics import CreateAPIView, GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_swagger.renderers import OpenAPIRenderer, SwaggerUIRenderer
from serializers import UserLoginSerializer, UserRegistrationSerializer
from validations_utils import ValidationException

# Create your views here.
@api_view()
@permission_classes((AllowAny,))
@renderer_classes([OpenAPIRenderer, SwaggerUIRenderer])
def schema_view(request):
    generator = schemas.SchemaGenerator(title="Rest Swagger")
    return Response(generator.get_schema(request=request))


class UserRegistrationAPIView(CreateAPIView):
    authentication_classes = ()
    permission_classes = ()
    serializer_class = UserRegistrationSerializer

    def create(self, request, *args, **kwargs):
        data = validations_utils.email_validation(
            request.data
        )  # Validates email id, it returns lower-cased email in data.
        data = validations_utils.password_validation(
            data
        )  # Validates password criteria.
        data["password"] = data["confirm_password"] = utils.hash_password(
            data["password"]
        )
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        user = serializer.instance
        token, created = Token.objects.get_or_create(user=user)
        data = serializer.data
        data["token"] = token.key
        headers = self.get_success_headers(serializer.data)
        return Response(data, status=status.HTTP_201_CREATED, headers=headers)


class UserLoginAPIView(GenericAPIView):
    authentication_classes = ()
    permission_classes = ()
    serializer_class = UserLoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.user
            try:
                login_user = utils.authenticate_user(
                    user, request.data
                )  # Authorizes the user and returns appropriate data.
            except ValidationException as e:  # Generic exception
                return Response(e.errors, status=e.status)
            return Response(login_user, status=status.HTTP_200_OK)
        else:
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST,)


class UserLogoutAPIView(APIView):
    permission_classes = [UserPermissions, IsAuthenticated]

    def post(self, request, *args, **kwargs):
        Token.objects.filter(user=request.user).delete()
        return Response(status=status.HTTP_200_OK)
