import json
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.middleware.csrf import get_token
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
from urllib.parse import urlparse
from django.contrib.auth.hashers import check_password
from django.contrib.auth import update_session_auth_hash
import random
from datetime import datetime

#import all models
from .models import *

# Create your views here.

def generate_random_color():
    random_character = "0123456789ABCDEF"
    color_hexadeximal = "#"
    for _ in range(6):
        color_hexadeximal += random.choice(random_character)
    return color_hexadeximal 

def get_favicon(url):
        try:
            domain = urlparse(url).netloc
            if domain.startswith("www."):
                domain = domain[4:]
            favicon_url = f"https://www.google.com/s2/favicons?domain={domain}&sz=64"
            return favicon_url
        except Exception as e:
            print(f"Error getting favicon: {e}")
            return "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%23999' d='M3.9 12c0-1.71 1.39-3.1 3.1-3.1h4V7H7c-2.76 0-5 2.24-5 5s2.24 5 5 5h4v-1.9H7c-1.71 0-3.1-1.39-3.1-3.1zM8 13h8v-2H8v2zm9-6h-4v1.9h4c1.71 0 3.1 1.39 3.1 3.1s-1.39 3.1-3.1 3.1h-4V17h4c2.76 0 5-2.24 5-5s-2.24-5-5-5z'/%3E%3C/svg%3E"

@ensure_csrf_cookie
def get_csrf_token(request):
    return JsonResponse({'detail': "CSRF cookie set"})
     

@api_view(['POST'])
def login_user(request):
    data = request.data
    email = data.get("email")
    password = data.get("password")
    user = authenticate(request, username=email, password=password)

    if user is not None:
        print(request.user)
        login(request, user)
        print(request.user)
        return Response(
            {"message": "User logged successfully"},
            status=status.HTTP_200_OK
        )
    else:
        return Response(
            {"error": "Invalid credentials"},
            status=status.HTTP_400_BAD_REQUEST
        )

@api_view(['POST'])
def register_user(request):
    data = request.data
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    if request.user.is_authenticated:
        return Response({"error": "You need to log out first"}, status=status.HTTP_400_BAD_REQUEST)
    if not name or not email or not password:
        return Response(
            {"error": "All fields are required."},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    if User.objects.filter(email=email).exists():
        return Response(
            {"error": "This email is already in use."},
            status=status.HTTP_400_BAD_REQUEST
            )
    
    color = generate_random_color()
    create_user = User.objects.create_user(
        username=email,
        first_name=name,
        email=email,
        password=password,
        color=color)
    create_user.save()
    login(request, create_user, backend='django.contrib.auth.backends.ModelBackend')

    return Response(
        {"message": "User registered successfully"},
        status=status.HTTP_201_CREATED
    )

"""LOGIN REQUIRED'S FUNCTIONS"""

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_user(request):
    if not request.user:
        return Response({"error":"You need to be logged in to log out."}, status=status.HTTP_403_FORBIDDEN)
    print(request.user)
    logout(request)
    print(request.user)
    return Response(
        {   "success": True,
            "message":"Logged out succesfully "},
        status=status.HTTP_200_OK
    )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_info(request):
    user = request.user
    print(f"Serializer: {user.serialize()}")
    return Response(user.serialize(), status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_sections(request):
    user = request.user
    if not user:
        return Response({"error":"Unauthorized user"}, status=status.HTTP_401_UNAUTHORIZED)
    get_all_sections = user.my_sections.all()
    return Response([section.serialize() for section in get_all_sections], status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def all_urls(request):
    try:
        urls=Urls_by_section.objects.filter(user_owner_urls=request.user)
        return Response([url.serialize() for url in urls], status=status.HTTP_200_OK)
    except Exception as e:
        print(f"Error: {e}")
        return Response({"Error":"Something went wrong"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def section_urls(request, section_id):
    try:
        section = Section.objects.get(id=section_id)

        if section.user_owner_section != request.user:
            return Response({"error": "You don't have permission to see these urls"}, status=status.HTTP_403_FORBIDDEN)
        urls = Urls_by_section.objects.filter(section=section_id)
        print([url.serialize() for url in urls])
        return Response([url.serialize() for url in urls], status=status.HTTP_200_OK)
    except:
        return Response({"error":"Section not found"}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_all_favorites(request):
    try:
        user = request.user
        favorites_urls = Urls_by_section.objects.filter(favorite=True, user_owner_urls=user)
        return Response([url.serialize() for url in favorites_urls], status=status.HTTP_200_OK)
    except:
        return Response({"error":"Something went wrong"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_section(request):
    try:    
        data = request.data
        new_section_name = data.get("section_name")
        if not new_section_name or not new_section_name.strip():
            return Response({"error": "Section name cannot be empty."}, status=status.HTTP_400_BAD_REQUEST)
        Section.objects.create(
            name_section = new_section_name,
            user_owner_section = request.user
        )
        return Response({
            "success": True,
            "message": "Section create succesfully."
        }, status=status.HTTP_201_CREATED)
    except:
        return Response({"error": "Something went wrong."}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_section(request, section_id):
    try:
        section = Section.objects.get(pk=section_id)
        if section.user_owner_section != request.user:
            return Response({"error":"You don't have permission to edit this url."},status=status.HTTP_403_FORBIDDEN)
        data = request.data
        new_section_name = data.get("new_section_name")
        if not new_section_name or not new_section_name.strip():
            return Response({"error": "Section name cannot be empty."}, status=status.HTTP_400_BAD_REQUEST)
        section.name_section = new_section_name
        section.save()
        return Response({
            "success": True,
            "message": "Section update succesfully.",
            "section": {
                "id": section.id,
                "name": section.name_section
            }   
        }, status=status.HTTP_200_OK)
    except: 
        return Response({"error": "The action could not be performed."}, status=status.HTTP_404_NOT_FOUND)
    
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])   
def delete_section(request, section_id):
    try:
        user = request.user
        section_to_delete = Section.objects.get(pk=section_id)
        if user != section_to_delete.user_owner_section:
            return Response({"Error":"You don't have permission to delete this section."}, status=status.HTTP_403_FORBIDDEN)
        section_to_delete.delete()
        return Response({
            "success": True,
            "message": "Section delete succesfully"
        }, status=status.HTTP_200_OK)
    except:
        return Response({"error":"Someting went wrong"})

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_url(request):
    try:    
        data = request.data
        new_url_name = data.get("url_name")
        new_url_link = data.get("url_link")
        section_id = data.get("section_id")
        
        if not new_url_name or not new_url_name.strip() or not new_url_link or not new_url_link.strip():
            return Response({"error": "Url fields cannot be empty."}, status=status.HTTP_400_BAD_REQUEST)
        new_url_name = new_url_name.strip()
        new_url_link = new_url_link.strip()
        validator = URLValidator()
        try:
            section = Section.objects.get(pk=section_id)            
        except Section.DoesNotExist:
            return Response({"error": "Section not found."}, status=status.HTTP_404_NOT_FOUND)
        try:
            validator(new_url_link)
        except ValidationError:
            return Response({"error":"Invalid URL."}, status=status.HTTP_400_BAD_REQUEST)

        if section.user_owner_section != request.user:
            return Response({"error": "You don't have permission to add an URL in this section."}, status=status.HTTP_403_FORBIDDEN) 

        favicon = get_favicon(new_url_link)
        Urls_by_section.objects.create(
            url_name = new_url_name,
            link = new_url_link,
            favicon = favicon,
            section = section,
            user_owner_urls = request.user
        )
        return Response({
            "success": True,
            "message": "Url create successfully."
        }, status=status.HTTP_201_CREATED)
    except Exception as e:
        print(f"Error creating URL: {e}")
        return Response({"error": "Something went wrong."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_url(request, url_id):
    try:
        data = request.data
        new_url_name = data.get("new_url_name")
        new_url_link = data.get("new_url_link")
        
        if not new_url_name or not new_url_name.strip()or not new_url_link or not new_url_link.strip() :
            return Response({"error": "Urls fields cannot be empty."}, status=status.HTTP_400_BAD_REQUEST)
        new_url_name = new_url_name.strip()
        new_url_link = new_url_link.strip()

        try:
            url = Urls_by_section.objects.get(pk=url_id)
        except Urls_by_section.DoesNotExist:
            return Response({"error": "Url not found."}, status=status.HTTP_404_NOT_FOUND)
        
        if url.user_owner_urls != request.user:
            return Response({"error":"You don't have permission to edit this URL."},status=status.HTTP_403_FORBIDDEN)

        if url.link != new_url_link:
            validator = URLValidator()
            try:
                validator(new_url_link)
            except ValidationError:
                return Response({"error":"Invalid URL."}, status=status.HTTP_400_BAD_REQUEST)
            favicon = get_favicon(new_url_link)
            url.favicon = favicon

        url.url_name = new_url_name
        url.link = new_url_link
        url.save()
        return Response({
            "success": True,
            "message": "Url update successfully.",
            "url": {
                "id": url.id,
                "name": url.url_name,                
            }   
        }, status=status.HTTP_200_OK)
    except Exception as e:
        print(f"Error editing URL: {e}")
        return Response({"error": "The action could not be performed."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])   
def delete_url(request, url_id):
    try:
        user = request.user
        url_to_delete = Urls_by_section.objects.get(pk=url_id)
        if user != url_to_delete.user_owner_urls:
            return Response({"Error":"You don't have permission to delete this URL."}, status=status.HTTP_403_FORBIDDEN)
        url_to_delete.delete()
        return Response({
            "success": True,
            "message": "URL delete succesfully."
        }, status=status.HTTP_200_OK)
    except Exception as e:
        print(f"Error deleting URL: {e}")
        return Response({"error":"Something went wrong."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def edit_user_info(request):
    try: 
        data = request.data
        new_name = data.get("new_first_name")
        new_username = data.get("new_username")
        new_color = data.get("color")
        user = request.user
        if not new_name or not new_name.strip() or not new_username or not new_username.strip() or not new_color:
            return Response({"error": "The fields cannot be empty."}, status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(username=new_username).exclude(id=user.id).exists():
            return Response({"error":"This email is already in use."}, status=status.HTTP_409_CONFLICT)
        new_username = new_username.strip()
        new_name = new_name.strip()
        user.username = new_username
        user.email = new_username
        user.first_name = new_name
        user.color = new_color
        user.save()
        return Response({
            "success": True,
            "message": "User updated successfully"
        })
    except Exception as e :
        print(f"Error: {e}")
        return Response({"error":"Something went wrong"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def change_password(request):
    try:
        data = request.data
        actual_password = data.get("actual_password")
        new_password = data.get("new_password")
        confirm_new_password = data.get("confirm_new_password")
        if not actual_password or not new_password or not confirm_new_password:
            return Response({"error":"The fields cannot be empty."}, status=status.HTTP_400_BAD_REQUEST)
        if not check_password(actual_password, request.user.password):
            return Response({"error": "Invalid credentials."}, status=status.HTTP_400_BAD_REQUEST)
        if new_password != confirm_new_password:
            return Response({"error":"New passwords do not match."}, status=status.HTTP_400_BAD_REQUEST)
        request.user.set_password(new_password)
        request.user.save()
        update_session_auth_hash(request, request.user)
        return Response({
            "success": True,
            "message": "Password changed successfully."
            }, status=status.HTTP_200_OK)
    except:
        return Response({"error": "Something went wrong."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def favorite_function(request):
    data = request.data
    url_id = data.get("url_id")
    if not url_id:
        return Response({"error": "'Url Id' is required."}, status=status.HTTP_400_BAD_REQUEST)
    try:
        url = Urls_by_section.objects.get(pk=url_id)
    except Urls_by_section.DoesNotExist:
        return Response({"error":"Url not found."}, status=status.HTTP_404_NOT_FOUND)
    if url.user_owner_urls != request.user:
        return Response({"error": "You don't have permission to change this url."}, status=status.HTTP_403_FORBIDDEN)
    favorite = data.get("favorite")
    if favorite is None:
        return Response({"error":"'favorite' field is required."}, status=status.HTTP_400_BAD_REQUEST)
    url.favorite = favorite
    url.save()

    message = ""
    if url.favorite:
        message = "Url added to favorite."
    else:
        message = "Url removed from favorites."

    return Response({
        "success": True,
        "message": message
        }, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_JSON_to_download(request):
    sections = Section.objects.filter(user_owner_section=request.user)
    data = {
        "version" : 1,
        "date_of_exported": datetime.now().strftime('%Y-%m-%d %H:%M:S'),
        "sections" : [section.json_export() for section in sections]
    }
    response = HttpResponse(
        json.dumps(data, indent=4),
        content_type="application/json"
    )
    response["Content-Disposition"] = 'attachment; filename="backup_sections.json"'
    return response


