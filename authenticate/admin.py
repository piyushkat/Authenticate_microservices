from django.contrib import admin
from authenticate.models import *
# Register your models here.
# class UserAdmin(admin.ModelAdmin):
#     list_display = ('email','first_name','last_name','phone_no')
    
# admin.site.register(User,UserAdmin)

admin.site.register(Profile)



admin.site.register(TokenUser)