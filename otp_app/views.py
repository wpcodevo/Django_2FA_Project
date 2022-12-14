from rest_framework.response import Response
from rest_framework import status, generics
from django.contrib.auth import authenticate
from otp_app.serializers import UserSerializer
from otp_app.models import UserModel
import pyotp


class RegisterView(generics.GenericAPIView):
    serializer_class = UserSerializer
    queryset = UserModel.objects.all()

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            try:
                serializer.save()
                return Response({"status": "success", 'message': "Registered successfully, please login"}, status=status.HTTP_201_CREATED)
            except:
                return Response({"status": "fail", "message": "User with that email already exists"}, status=status.HTTP_409_CONFLICT)
        else:
            return Response({"status": "fail", "message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(generics.GenericAPIView):
    serializer_class = UserSerializer
    queryset = UserModel.objects.all()

    def post(self, request):
        data = request.data
        email = data.get('email')
        password = data.get('password')

        user = authenticate(username=email.lower(), password=password)

        if user is None:
            return Response({"status": "fail", "message": "Incorrect email or password"}, status=status.HTTP_400_BAD_REQUEST)

        if not user.check_password(password):
            return Response({"status": "fail", "message": "Incorrect email or password"}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.serializer_class(user)
        return Response({"status": "success", "user": serializer.data})


class GenerateOTP(generics.GenericAPIView):
    serializer_class = UserSerializer
    queryset = UserModel.objects.all()

    def post(self, request):
        data = request.data
        user_id = data.get('user_id', None)
        email = data.get('email', None)

        user = UserModel.objects.filter(id=user_id).first()
        if user == None:
            return Response({"status": "fail", "message": f"No user with Id: {user_id} found"}, status=status.HTTP_404_NOT_FOUND)

        otp_base32 = pyotp.random_base32()
        otp_auth_url = pyotp.totp.TOTP(otp_base32).provisioning_uri(
            name=email.lower(), issuer_name="codevoweb.com")

        user.otp_auth_url = otp_auth_url
        user.otp_base32 = otp_base32
        user.save()

        return Response({'base32': otp_base32, "otpauth_url": otp_auth_url})


class VerifyOTP(generics.GenericAPIView):
    serializer_class = UserSerializer
    queryset = UserModel.objects.all()

    def post(self, request):
        message = "Token is invalid or user doesn't exist"
        data = request.data
        user_id = data.get('user_id', None)
        otp_token = data.get('token', None)
        user = UserModel.objects.filter(id=user_id).first()
        if user == None:
            return Response({"status": "fail", "message": f"No user with Id: {user_id} found"}, status=status.HTTP_404_NOT_FOUND)

        totp = pyotp.TOTP(user.otp_base32)
        if not totp.verify(otp_token):
            return Response({"status": "fail", "message": message}, status=status.HTTP_400_BAD_REQUEST)
        user.otp_enabled = True
        user.otp_verified = True
        user.save()
        serializer = self.serializer_class(user)

        return Response({'otp_verified': True, "user": serializer.data})


class ValidateOTP(generics.GenericAPIView):
    serializer_class = UserSerializer
    queryset = UserModel.objects.all()

    def post(self, request):
        message = "Token is invalid or user doesn't exist"
        data = request.data
        user_id = data.get('user_id', None)
        otp_token = data.get('token', None)
        user = UserModel.objects.filter(id=user_id).first()
        if user == None:
            return Response({"status": "fail", "message": f"No user with Id: {user_id} found"}, status=status.HTTP_404_NOT_FOUND)

        if not user.otp_verified:
            return Response({"status": "fail", "message": "OTP must be verified first"}, status=status.HTTP_404_NOT_FOUND)

        totp = pyotp.TOTP(user.otp_base32)
        if not totp.verify(otp_token, valid_window=1):
            return Response({"status": "fail", "message": message}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'otp_valid': True})


class DisableOTP(generics.GenericAPIView):
    serializer_class = UserSerializer
    queryset = UserModel.objects.all()

    def post(self, request):
        data = request.data
        user_id = data.get('user_id', None)

        user = UserModel.objects.filter(id=user_id).first()
        if user == None:
            return Response({"status": "fail", "message": f"No user with Id: {user_id} found"}, status=status.HTTP_404_NOT_FOUND)

        user.otp_enabled = False
        user.otp_verified = False
        user.otp_base32 = None
        user.otp_auth_url = None
        user.save()
        serializer = self.serializer_class(user)

        return Response({'otp_disabled': True, 'user': serializer.data})
