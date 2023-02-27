import re
import random
from rest_framework.response import Response



def email_otp():
  r1 = random.randint(100000,999999)
  return r1


def Validate_Password(password):
    try:
    
        regex = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$"
        if (re.fullmatch(regex, password)):
            return True
        return False
    except:
        return Response({"msg": "Password is empty"})