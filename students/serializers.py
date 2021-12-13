import json

from rest_framework import serializers
from .models import Student
from django.contrib.auth import get_user_model
from dj_rest_auth.registration.serializers import RegisterSerializer
from rest_framework.exceptions import ValidationError
from allauth.account.adapter import get_adapter
from allauth.account.utils import setup_user_email
from dj_rest_auth.serializers import LoginSerializer, UserDetailsSerializer, PasswordResetSerializer
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model, authenticate

import logging
logger = logging.getLogger(__name__)

User = get_user_model()

class StudentSerializer(serializers.ModelSerializer):

    class Meta:
        model = Student
        fields = ('pk', 'first_name', 'last_name', 'email', 'classroom')

class CustomRegisterSerializer(RegisterSerializer):
    username = serializers.CharField()
    email = serializers.EmailField(required=True)
    password1 = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    def validate_username(self, username):
        username = get_adapter().clean_username(username)
        return username

    def validate_email(self, email):
        email = get_adapter().clean_email(email)
        users = User.objects.filter(email__iexact=email)
        # if allauth_settings.UNIQUE_EMAIL:
        if users:
            raise serializers.ValidationError(
                _("A user already exists with this e-mail address."))
        return email

    def validate_password1(self, password):
        return get_adapter().clean_password(password)

    def validate(self, data):
        if data['password1'] != data['password2']:
            raise serializers.ValidationError(_("The two password fields didn't match."))
        return data

    def custom_signup(self, request, user):
        pass

    def get_cleaned_data(self):
        return {
            'username': self.validated_data.get('username', ''),
            'password1': self.validated_data.get('password1', ''),
            'email': self.validated_data.get('email', '')
        }

    def save(self, request):
        adapter = get_adapter()
        user = adapter.new_user(request)
        self.cleaned_data = self.get_cleaned_data()
        adapter.save_user(request, user, self)
        self.custom_signup(request, user)
        setup_user_email(request, user, [])
        return user


# class CustomLoginSerializer(LoginSerializer):
#     """
#     Default serializer used for user login. It will use
#     :ref:`user-login-fields-setting` setting to compare the login
#     to the user login fields defined by this setting.
#     """

#     # username = serializers.CharField(required=False, allow_blank=True)
#     email = serializers.EmailField(required=False, allow_blank=True)
#     password = serializers.CharField(
#         style={"input_type": "password"}, required=False, allow_blank=True
#     )

#     class Meta():
#         fields = "__all__"

#     def authenticate(self, **kwargs):
#         return authenticate(self.context['request'], **kwargs)    

#     def validate_email(self, data):
#         email = data
#         users = User.objects.filter(email__iexact=email)
#         print(users, "email")
#         print(email)
#         if not users:
#             raise ValidationError(_("A user with this email does not exists"))
#         print(email.lower)    
#         return email.lower()


#     # def get_auth_user_using_allauth(self, email, password):
#     #     # user = None
#     #     # Authentication through email
#     #     print(email, "checking")
#     #     print(password, "password checking")
#     #     # user = None

#     #     if email and password is not None:
#     #         print(email, password)
#     #         user = self.authenticate(email=email, password=password)
#     #         print(user, "jfbsdfhdslanfoadsa")
#     #     print(user, "data")
#     #     return user

#     # def get_auth_user(self, email, password):
#     #     """
#     #     Retrieve the auth user from given POST payload by using
#     #     either `allauth` auth scheme or bare Django auth scheme.

#     #     Returns the authenticated user instance if credentials are correct,
#     #     else `None` will be returned
#     #     """
#     #     logger.info("Auth User validate %s", email)
#     #     return self.get_auth_user_using_allauth(email, password)

#     def validate(self, attrs):
#         email = attrs.get("email")
#         password = attrs.get("password")
#         user = self.get_auth_user(email, password)

#         if not user:
#             msg = _("Entered email or password is incorrect.")
#             raise ValidationError(msg)


#         attrs["user"] = user
#         logger.info("User data: [ %s ]", user)
#         return attrs
