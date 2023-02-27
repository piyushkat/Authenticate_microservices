from rest_framework import serializers
from django.contrib.auth.models import User 
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework_simplejwt.tokens import RefreshToken,TokenError
from authenticate.models import *
from authenticate.utils import Util


class UserRegistrationSerializer(serializers.ModelSerializer):
    # We are writing this becoz we need confirm password field in our Registratin Request
    class Meta:
        model = User
        fields = ('email','first_name', 'last_name','password')


class VerifyOtpSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['user_id','auth_token']


# user login serilaizer
class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255,required=True)
    password = serializers.CharField(required=True)
    class Meta:
        model = User
        fields = ['email', 'password']

        
# user send password email serializer
class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            # generate token for send email for password reset
            token = PasswordResetTokenGenerator().make_token(user)
            # generate link for forntend url for reset user password
            link = 'http://localhost:3000/api/user/reset/'+uid+'/'+token
            # Send EMail
            body = 'Click Following Link to Reset Your Password '+link
            data = {
                'subject': 'Reset Your Password',
                'body': body,
                'to_email': user.email
            }
            Util.send_email(data)
            return attrs
        else:
            raise serializers.ValidationError('You are not a Registered User')


# user password reset serializer
class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(
        max_length=255, style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')
            if password != password2:
                raise serializers.ValidationError(
                    "Password and Confirm Password doesn't match")
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError(
                    'Token is not Valid or Expired')
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise serializers.ValidationError('Token is not Valid or Expired')


# user changepassword serializer
class UserChangePasswordSerializer(serializers.Serializer):
    class Meta:
        model = User
        fields = ['password']
        

class UserUpdateProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

class TokenSerializer(serializers.Serializer):
    user = serializers.CharField()
    access_token = serializers.CharField()
    # refresh_token = serializers.CharField()


