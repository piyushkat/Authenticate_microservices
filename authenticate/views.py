import environ
import datetime
from rest_framework import status
from authenticate.helper import *
from django.utils import timezone
from authenticate.serializer import *
from django.core.mail import send_mail
from datetime import datetime, timedelta
from rest_framework.response import Response
from django.contrib.auth import authenticate
from rest_framework.generics import GenericAPIView
from django.contrib.auth.hashers import make_password
from rest_framework_simplejwt.tokens import RefreshToken


# importing and cofigure dot env file
env=environ.Env()
environ.Env.read_env()
EMAIL_FROM = env('EMAIL_FROM')


# validation for unique user email
def unique_email(email):
  """
  :return: All the users have the unique Email id.
  """
  res = User.objects.filter(email = email) # Get the Email from the User table. 
  return res


class UserRegistrationView(GenericAPIView):
    serializer_class = UserRegistrationSerializer
    def post(self,request):
        confirm_password = request.data.get('password1') #Request the Email from the user)
        email = request.data.get('email') #Request the Email from the user
        password = request.data.get('password') # Request the password from the user
        first_name = request.data.get('first_name') # Request th0e first name from the user
        last_name = request.data.get('last_name') # Request the last name from the user
        pass_bool = Validate_Password(password) # Validate the password.
        if not pass_bool:
            return Response({'msg': 'Enter valid passoword'})
        res = unique_email(email) # Email is unique for every user.
        if res:
            return Response({'msg': 'Email or username already Exists'})
        if password!=confirm_password:
            return Response({'msg': 'Password doesnot match'})
        serializer = UserRegistrationSerializer(data=request.data) # serializer the data
        serializer.is_valid(raise_exception=True) # if fields is valid
        user = User.objects.create(username=email,password=password,email=email,first_name=first_name,last_name=last_name)
        user.password= make_password(password)
        user.save()
        otp = email_otp() # six digits otp send to your email.
        user_obj = User.objects.get(username=email) # Get the username from the user table.
        profile = Profile(user=user_obj,auth_token=otp)
        profile.save()
        # sending otp in user email while register
        EMAIL_FROM = env('EMAIL_FROM')
        EMAIL_FROM = env('EMAIL_FROM')
        subject = 'Verify Email Otp '
        message = f'Hi {first_name,last_name}, OTP for Email Verification is {otp}.'
        email_from = EMAIL_FROM
        recipient_list = [email]
        send_mail( subject, message, email_from, recipient_list)
        return Response({'msg':'Registration Successfull, A OTP Verification code has been send to your Email'}, status = status.HTTP_201_CREATED)


class VerifyOtp(GenericAPIView):
  serializer_class = VerifyOtpSerializer
  def post(self,request):
    """
    :return: Send OTP through Email When the user hit the register api. 
    """
    user = request.data.get('user')
    auth_token = request.data.get('auth_token')
    if not user or not auth_token:
      return Response({'msg': 'Invalid parameters'})
    res = Profile.objects.filter(user_id=user).values()
    if res:  #checks if there is any user with this id
      otp_time=res[0]['created_at']
      time_change = timedelta(days=1)
      new_time=otp_time+time_change
      now = datetime.now(timezone.utc)
      if new_time>= now:
          if str(res[0]['user_id'])==user and res[0]['auth_token']==auth_token:
            res.update(is_verified=True)
            return Response({"status": "Otp Verified"}, status = status.HTTP_200_OK)
          return Response({"status": "Otp Incorrect"}, status = status.HTTP_404_NOT_FOUND)
      return Response({"status": "Verification OTP Expired"}, status = status.HTTP_408_REQUEST_TIMEOUT)
    return Response({"status": "No user found"}, status = status.HTTP_404_NOT_FOUND)


class VerifyEmailOtpSecondTime(GenericAPIView):
  serializer_class = VerifyOtpSerializer                    
  def post(self,request):
    """
    :return: send OTP second time for email verification when user is to forgot to Enter the OTP for first time.
    """
    email = request.data.get('email') # Enter the same mail you enter registration time
    if not email: # check the parameter of the email
      return Response({'msg': 'Invalid parameters'})
    res = User.objects.filter(email=email).values('id') # Get the Email from the user table
    if res:
      otp = email_otp() # six digits otp send to your email.
      EMAIL_FROM = env('EMAIL_FROM')
      EMAIL_FROM = env('EMAIL_FROM')
      subject = 'Verify Email Otp '
      message = f'Hi {email}, OTP for Email Verification is {otp}.'
      email_from = EMAIL_FROM
      recipient_list = [email]
      send_mail( subject, message, email_from, recipient_list) # send otp thrugh email if the email is stored in the database
      profile  = Profile.objects.get(user=res[0]['id'])
      profile.auth_token=otp
      profile.created_at=datetime.datetime.now(timezone.utc)
      profile.save()
      return Response({'msg':' A Verification code has been send to your Email'}, status = status.HTTP_200_OK)
    return Response({'msg':"Email Doesn't exists"}, status==status.HTTP_404_NOT_FOUND)

class UserLoginView(GenericAPIView):
    serializer_class = UserLoginSerializer
    def post(self, request):
      email = request.data.get('email')
      password = request.data.get('password')
      if not email or not password:
        return Response({"msg": "Email Password Incorrect"}, status=status.HTTP_400_BAD_REQUEST)
      user = User.objects.filter(email=email).first()
      if user and not user.is_superuser:
        try:
            res = Profile.objects.get(user=user)
        except:
            return Response({'msg': 'Please continue with google to login'})
        if res and not res.is_verified:
            return Response({'msg': 'email not verified'})
        user = authenticate(username=email, password=password)
        if user is not None:
            refresh = RefreshToken.for_user(user) # Generate a new refresh token
            access = refresh.access_token # Extract the access token from the refresh token
            response_data = {
                'msg': 'Token Generated',
                'access_token': str(access), # Convert the token to a string before adding it to the dictionary
                'refresh_token':str(refresh)
            }
            return Response(response_data, status=status.HTTP_200_OK)
        else:
            return Response({'errors': {'non_field_errors': ['email or Password is not Valid']}}, status=status.HTTP_404_NOT_FOUND)
      else:
          return Response({'msg': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)