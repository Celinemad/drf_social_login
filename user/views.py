import jwt
from rest_framework.views import APIView
from .serializers import *
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework import status
from rest_framework.response import Response
from django.contrib.auth import authenticate
from django.shortcuts import render, get_object_or_404
from loginproject.settings import SECRET_KEY

# UserViewSet
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from .serializers import *

# 구글 로그인
from django.shortcuts import redirect
import os

# google_callback
from json import JSONDecodeError
from django.http import JsonResponse
import requests
# import os
# from rest_framework import status
from .models import *
from allauth.socialaccount.models import SocialAccount

class RegisterAPIView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)  # 시리얼아리저 사용해서 유저 저장
        if serializer.is_valid():
            user = serializer.save()                    # 저장

            # jwt 토큰 접근
            token = TokenObtainPairSerializer.get_token(user)
            refresh_token = str(token)
            access_token = str(token.access_token)
            res = Response(
                {
                    "user": serializer.data,
                    "message": "register success",
                    "token": {
                        "access": access_token,
                        "refresh": refresh_token,
                    },
                },
                status=status.HTTP_200_OK
            )

            # jwt 토큰을 받아서 쿠키에 저장
            res.set_cookie("access", access_token, httponly=True)   # httponly=True : JavaScript로 쿠키를 조회할 수 없게 함
            res.set_cookie("refresh", refresh_token, httponly=True)     # XSS로부터 안전해지지만, CSRF로부터 취약해짐 => CSRF 토큰을 같이 사용해야 함

            return res
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AuthAPIView(APIView):

    # 유저 정보 확인
    def get(self, request):
        try:
            # access token을 decode 해서 유저 id 추출 => 유저 식별
            access = request.COOKIES['access']
            payload = jwt.decode(access, SECRET_KEY, algorithms=['HS256'])
            pk = payload.get('user_id')
            user = get_object_or_404(User, pk=pk)
            serializer = UserSerializer(instance=user)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except(jwt.exceptions.ExpiredSignatureError):
            # 토큰 만료 시 토큰 갱신
            data = {'refresh': request.COOKIES.get('refresh', None)}
            serializer = TokenRefreshSerializer(data=data)
            if serializer.is_valid(raise_exception=True):
                access = serializer.data.get('access', None)
                refresh = serializer.data.get('access', None)
                payload = jwt.decode(access, SECRET_KEY, algorithms=['HS256'])
                pk = payload.get('user_id')
                user = get_object_or_404(User, pk=pk)
                serializer = UserSerializer(instance=user)
                res = Response(serializer.data, status=status.HTTP_200_OK)
                res.set_cookie('access', access)
                res.set_cookie('refresh', refresh)
                return res
            raise jwt.exceptions.InvalidTokenError
        
        except(jwt.exceptions.InvalidTokenError):
            # 사용 불가능한 토큰일 때
            return Response(status=status.HTTP_400_BAD_REQUEST)
        
    # 로그인
    def post(self, request):

        # 유저 인증
        user = authenticate(
            email=request.data.get("email"), 
            password=request.data.get("password")
        )

        # 이미 회원가입이 된 유저일 때
        if user is not None:
            serializer = UserSerializer(user)
            # jwt 토큰 접근
            token = TokenObtainPairSerializer.get_token(user)
            refresh_token = str(token)
            access_token = str(token.access_token)
            res = Response(
                {
                    "user": serializer.data,
                    "message": "login success",
                    "token": {
                        "access": access_token,
                        "refresh": refresh_token, 
                    },
                },
                status=status.HTTP_200_OK,
            )
            # jwt 토큰 => 쿠키에 저장
            res.set_cookie("access", access_token, httponly=True)
            res.set_cookie("refresh", refresh_token, httponly=True)
            return res
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        
    # 로그아웃
    def delete(self,request):
        # 쿠키에 저장된 토큰 삭제 => 로그아웃 처리
        response = Response(
            {
            "message": "Logout success"
            },
            status=status.HTTP_202_ACCEPTED
        )
        response.delete_cookie("access")
        response.delete_cookie("refresh")
        return response
    
'''
JWT는 서버 쪽에서 로그아웃을 할 수 없고, 한번 발급된 JWT 토큰을 강제로 삭제하거나 무효화할수도 없다. 
그래서 보통 JWT 토큰의 유효기간을 짧게 하거나, 토큰을 DB에 보존하고 매 요청마다 로그아웃으로 인해 DB에서 삭제된 토큰인지 아닌지를 확인하는 방법을 쓴다고 한다. 
그런데 이 방법들은 너무 귀찮기도 하고 복잡해서, 쿠키를 삭제하면 서버에서 유저를 확인할 방법이 없어지니까 단순하게 쿠키에 담긴 토큰을 지워주는 방향으로 갔다. 

유저정보는 별도로 authorization에 jwt 토큰을 포함시켜주지 않아도 쿠키에 저장된 토큰으로 해당 사용자의 정보를 보여준다.
'''

# jwt 토큰 인증 확인용 뷰셋
# Header - Authorization : Bearer <발급받은토큰>
class UserViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = User.objects.all()
    serializer_class = UserSerializer


# 구글 소셜로그인 변수 설정
state = os.environ.get('STATE')
BASE_URL = 'http://localhost:8000/'
GOOGLE_CALLBACK_URI = BASE_URL + 'user/google/callback/'

# 구글 로그인
def google_login(request):
    scope = "https://www.googleapis.com/auth/userinfo.email"
    client_id = os.environ.get("SOCIAL_AUTH_GOOGLE_CLIENT_ID")
    
    # 이 url로 들어가면 구글 로그인 창이 뜨고, 알맞은 아이디와 비번을 입력하면 callback URI로 코드값이 들어감
    return redirect(f"https://accounts.google.com/o/auth2/v2/auth?client_id={client_id}&response_type=code&redirect_uri={GOOGLE_CALLBACK_URI}&scope={scope}")

# access token & email 요청 -> 회원가입/로그인 & jwt 발급
def google_callback(request):
    client_id = os.environ.get('SOCIAL_AUTH_GOOGLE_CLIENT_ID')
    client_secret = os.environ.get('SOCIAL_AUTH_GOOGLE_SECRET')
    code = request.GET.get('code')

    # 1. 받은 코드로 구글에 access token 요청
    token_req = requests.post(f"https://oauth2.googleapis.com/token?client_id={client_id}&client_secret={client_secret}&code={code}&grant_type=authorization_code&redirect_uri={GOOGLE_CALLBACK_URI}&state={state}")

    ### 1-1. json으로 변환 & 에러 부분 파싱
    token_req_json = token_req.json()
    error = token_req_json.get("error")

    ### 1-2. 에러 발생 시 종료
    if error is not None:
        raise JSONDecodeError(error)
    
    ### 1-3. 성공 시 access_token 가져오기
    access_token = token_req_json.get('access_token')
    
    #------------------------------------------------------------