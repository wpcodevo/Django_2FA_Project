from django.urls import path
from otp_app.views import (RegisterView, LoginView,
                           GenerateOTP, VerifyOTP, ValidateOTP, DisableOTP)

urlpatterns = [
    path('register', RegisterView.as_view()),
    path('login', LoginView.as_view()),
    path('otp/generate', GenerateOTP.as_view()),
    path('otp/verify', VerifyOTP.as_view()),
    path('otp/validate', ValidateOTP.as_view()),
    path('otp/disable', DisableOTP.as_view()),
]
