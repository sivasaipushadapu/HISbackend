from django.shortcuts import render
from django.conf import settings
from dj_rest_auth.registration.serializers import RegisterSerializer
# from .models import Student
from rest_framework.generics import ListCreateAPIView,  RetrieveUpdateDestroyAPIView
from dj_rest_auth.registration.views import RegisterView, VerifyEmailView
from rest_framework import status, viewsets, filters
from rest_framework.permissions import IsAuthenticated
from .serializers import  User
from django.core.mail import send_mail
from django.core.mail import EmailMultiAlternatives
from django.core import mail
from django.template.loader import get_template, render_to_string
from rest_framework.generics import CreateAPIView, GenericAPIView, ListAPIView
from django.views.decorators.debug import sensitive_post_parameters
from django.utils.decorators import method_decorator
from rest_framework.response import Response
from allauth.account.utils import complete_signup, send_email_confirmation
from dj_rest_auth.app_settings import (
    JWTSerializer, TokenSerializer, create_token,
)
from dj_rest_auth.models import TokenModel
from dj_rest_auth.registration.serializers import (
    SocialAccountSerializer, SocialConnectSerializer, SocialLoginSerializer,
    VerifyEmailSerializer, ResendEmailVerificationSerializer

)
from dj_rest_auth.utils import jwt_encode
from .serializers import CustomRegisterSerializer
from dj_rest_auth.views import LoginView
# Create your views here.


sensitive_post_parameters_m = method_decorator(
    sensitive_post_parameters('password1', 'password2'),
)

def send_email_agent(id):
    try:
        agent = User.objects.get(id=id)
        print("agent-task", agent)
        text_content = ""
        subject = '[FyndEasy] Your request for agent code has been recieved.'
        message = get_template('agentcode_mail_template.html')
        html_content = message.render({'name': agent.name, 'email': agent.email, 'phone_number': agent.phone_number})
        email_from = settings.EMAIL_HOST_USER
        recipient_list = [
            agent.email
        ]
        msg = EmailMultiAlternatives(subject, text_content, email_from, recipient_list)
        msg.attach_alternative(html_content, "text/html")
        return msg.send()
        # ...
    except User.DoesNotExist:
        return "something fishy"

    
class CustomRegisterView(RegisterView):
    serializer_class = CustomRegisterSerializer
    # permission_classes = register_permission_classes()
    # token_model = TokenModel
    throttle_scope = 'dj_rest_auth'

    @sensitive_post_parameters_m
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get_response_data(self, user):

        if getattr(settings, 'REST_USE_JWT', False):
            data = {
                'user': user,
                'access_token': self.access_token,
                'refresh_token': self.refresh_token,
            }
            return JWTSerializer(data, context=self.get_serializer_context()).data
        else:
            return TokenSerializer(user.auth_token, context=self.get_serializer_context()).data

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)

        return Response(
            self.get_response_data(user),
            status=status.HTTP_201_CREATED,
            headers=headers,
        )

    def perform_create(self, serializer):
        user = serializer.save(self.request)
        if getattr(settings, 'REST_USE_JWT', False):
            self.access_token, self.refresh_token = jwt_encode(user)
        else:
            create_token(self.token_model, user, serializer)
        ser = serializer.data
        email = serializer['email']
        print(ser)
        return user 