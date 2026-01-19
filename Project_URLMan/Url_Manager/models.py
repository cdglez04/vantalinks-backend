from django.db import models
from django.contrib.auth.models import AbstractUser
from django.forms import CharField

# Create your models here.

class User(AbstractUser):
    color = models.CharField(max_length=32, null=True)

    def serialize(self):
        data = {
            "id": self.id,
            "username": self.username,
            "first_name": self.first_name,
            "date_joined": self.date_joined.strftime("%B %Y"),
            "color": self.color,
            "sections_count": self.my_sections.count(),
            "urls_count": self.my_urls.count(),   
            "favorites_urls_count": self.my_urls.filter(favorite=True).count()
        }
        return data


class Section(models.Model):
    name_section = models.CharField(max_length=256)
    date_created = models.DateTimeField(auto_now_add=True)
    user_owner_section = models.ForeignKey(User, on_delete=models.CASCADE, related_name="my_sections", null=True )

    def serialize(self):
        data = {
            "id": self.id,
            "name_section": self.name_section,
            "date_created": self.date_created,
            "user_owner_section": self.user_owner_section.id   
        }

        return data

    def json_export(self):
        urls_data = []

        for url in self.urls_by_this_section.all():
            urls_data.append({
                "url_name": url.url_name,
                "link": url.link,
                "favicon": url.favicon,
            })

        return  {
            "name_section": self.name_section,
            "urls" : urls_data
        }

class Urls_by_section(models.Model):
    url_name = models.CharField(max_length=256)
    link = models.URLField(max_length=200)
    favicon = models.URLField(max_length=200, blank=True)
    favorite = models.BooleanField(default=False)
    section = models.ForeignKey(Section, on_delete=models.CASCADE, related_name="urls_by_this_section", null=True)
    user_owner_urls = models.ForeignKey(User, on_delete=models.CASCADE, related_name="my_urls", null=True )

    def serialize(self):
        data = {
            "id": self.id,
            "url_name": self.url_name,
            "link": self.link,
            "favicon": self.favicon,
            "favorite": self.favorite,
            "section_id": self.section.id if self.section else None,
            "section_name": self.section.name_section if self.section else None,
            "user_owner_urls": self.user_owner_urls.id if self.user_owner_urls else None,
        }
        return data