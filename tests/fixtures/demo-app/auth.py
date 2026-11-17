from jose import JWTError, jwt

SECRET_KEY = "demo-secret"
ALGORITHM = "HS256"


# 로그인한 사용자에게 토큰 발급
def create_token(user_id):
    return jwt.encode({"sub": user_id}, SECRET_KEY, algorithm=ALGORITHM)


# 요청에 담긴 토큰 검증
def verify_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None
