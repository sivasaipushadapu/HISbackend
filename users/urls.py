from django.urls import path, re_path
from django.conf import settings
from dj_rest_auth.registration.views import RegisterView, VerifyEmailView
from dj_rest_auth.views import LoginView, LogoutView, PasswordResetView, PasswordResetConfirmView
from allauth.account.views import ConfirmEmailView
from django.views.generic import TemplateView
from django.conf.urls import include, url
from django.views.static import serve
from students.views import CustomRegisterView



urlpatterns = [
   url(r'^account-confirm-email/(?P<key>[-:\w]+)/$', TemplateView.as_view(),
   name='account_confirm_email'),
   path('auth/', include('dj_rest_auth.urls')),
   path('auth/registration/', include('dj_rest_auth.registration.urls')),
   path('password-reset-confirm/<uidb64>/<token>/',
      PasswordResetConfirmView.as_view(), name='password_reset_confirm'), 
   path('siva/', CustomRegisterView.as_view(), name='homepage'),
   url(r'^media/(?P<path>.*)$', serve,{'document_root':       settings.MEDIA_ROOT}), 
   url(r'^static/(?P<path>.*)$', serve,{'document_root': settings.STATIC_ROOT}), 

# 
]