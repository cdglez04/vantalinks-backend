from django.contrib import admin
from .models import *

# Register your models here.

class UserAdmin(admin.ModelAdmin):
    list_display=["username", "email", "date_joined"]

class SectionAdmin(admin.ModelAdmin):
    list_display=["name_section", "date_created", "user_owner_section"]

class Urls_by_sectionAdmin(admin.ModelAdmin):
    list_display=["url_name", "link", "favorite", "favicon", "user_owner_urls"]

admin.site.register(User, UserAdmin)
admin.site.register(Section, SectionAdmin)
admin.site.register(Urls_by_section, Urls_by_sectionAdmin)