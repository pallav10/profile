# -*- coding: utf-8 -*-
from urllib.parse import urljoin

import coreapi
import yaml

from rest_framework.schemas import SchemaGenerator

from api.permissions import IsAuthenticated, UserPermissions

from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.generics import CreateAPIView, GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_swagger.renderers import OpenAPIRenderer, SwaggerUIRenderer

from api.utils import authenticate_user
from api.serializers import (
    UserLoginSerializer,
    UserRegistrationSerializer,
    UserProfileSerializer,
)
from api.validations_utils import (
    ValidationException,
    email_validation,
    password_validation,
)


# Create your views here.
class CustomSchemaGenerator(SchemaGenerator):
    def get_link(self, path, method, view):
        fields = self.get_path_fields(path, method, view)
        yaml_doc = None
        if view and view.__doc__:
            try:
                yaml_doc = yaml.load(view.__doc__)
            except:
                yaml_doc = None
        # Extract schema information from yaml

        if yaml_doc and type(yaml_doc) != str:
            _method_desc = yaml_doc.get("description", "")
            params = yaml_doc.get("parameters", [])

            for i in params:
                _name = i.get("name")
                _desc = i.get("description")
                _required = i.get("required", False)
                _type = i.get("type", "string")
                _location = i.get("location", "form")
                field = coreapi.Field(
                    name=_name,
                    location=_location,
                    required=_required,
                    description=_desc,
                    type=_type,
                    example=None,
                    schema=None,
                )
                fields.append(field)
        else:

            _method_desc = view.__doc__ if view and view.__doc__ else ""
            fields += self.get_serializer_fields(path, method, view)

        fields += self.get_pagination_fields(path, method, view)
        fields += self.get_filter_fields(path, method, view)

        if fields and any([field.location in ("form", "body") for field in fields]):
            encoding = self.get_encoding(path, method, view)
        else:
            encoding = None

        if self.url and path.startswith("/"):
            path = path[1:]

        return coreapi.Link(
            url=urljoin(self.url, path),
            action=method.lower(),
            encoding=encoding,
            fields=fields,
            description=_method_desc,
        )


class SwaggerSchemaView(APIView):
    exclude_from_schema = True
    permission_classes = [AllowAny]
    renderer_classes = [OpenAPIRenderer, SwaggerUIRenderer]

    def get(self, request):
        generator = CustomSchemaGenerator()
        schema = generator.get_schema(request=request)
        return Response(schema)


class UserRegistrationAPIView(CreateAPIView):
    authentication_classes = ()
    permission_classes = ()
    serializer_class = UserRegistrationSerializer

    def create(self, request, *args, **kwargs):
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
                login_user = authenticate_user(
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


class UserProfileView(APIView):
    permission_classes = [UserPermissions, IsAuthenticated]
    serializer_class = UserProfileSerializer
    """
    Retrieve a user instance.
    """

    def get(self, request):
        serializer = self.serializer_class(request.auth.user)
        return Response(serializer.data, status=status.HTTP_200_OK)
