from django.apps import AppConfig


class DynamicappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'dynamicapp'
