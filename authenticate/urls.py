from django.urls import path
from authenticate.views import *

urlpatterns = [
    path('verifyotp',VerifyOtp.as_view(), name='verifyotp'),
    path('signup',UserRegistrationView.as_view(), name='signup'),
    path('verifyemail',VerifyEmailOtpSecondTime.as_view(), name='verifyemail'),
    path('signin',UserLoginView.as_view(), name='signin'),
    path('gettoken',TokenUserGet.as_view(), name='gettoken'),

]

