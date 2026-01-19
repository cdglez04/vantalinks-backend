from django.urls import path

from . import views

urlpatterns = [
    #API Routes
    path("csrf/", views.get_csrf_token, name="csrf"),
    #Post Routes
    path("login/", views.login_user, name="login_user"),
    path("register/", views.register_user, name="register_user"),
    path("logout/", views.logout_user, name="logout_user"),
    #Show info
    path("main/user_info/", views.user_info, name="user_info"),
    path("main/user_sections/", views.user_sections, name="user_sections"),
    path("main/all_urls/", views.all_urls, name="all_urls"),
    path("main/urls_by_sections/<int:section_id>/", views.section_urls, name="urls_by_section"),
    #Create info
    path("main/create_section/", views.create_section, name="create_section"),
    path("main/create_url/", views.create_url, name="create_url"),
    #Update Info
    path("main/update_section/<int:section_id>/", views.update_section, name="update_section"),
    path("main/edit_url/<int:url_id>/", views.update_url, name="update_url"),
    path("main/edit_user_info/", views.edit_user_info, name="edit_user_info"),
    #Delete Info
    path("main/delete_section/<int:section_id>/", views.delete_section, name="delete_section"),
    path("main/delete_url/<int:url_id>/", views.delete_url, name="delete_url"),
    #Change password
    path("main/change_password/", views.change_password, name="change_password"),
    #Favorite Url
    path("main/all_favorites/", views.get_all_favorites, name="get_all_favorites"),
    path("main/favorite/", views.favorite_function, name="set_favorite"),
    #Json Backup
    path("main/backup_json/",views.get_JSON_to_download, name="backup_json"),
]