"""XT01 URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path,include
from rest_framework import routers
# router = routers.DefaultRouter()
from UserAdministration import views


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/',include('UserAdministration.urls')),
    path('reset/<uidb64>/<token>/',views.PasswordTokenCheckApiView.as_view(),name='password_reset_confirm'), # verifying token

    # path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    # path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh')
    # path('', include(router.urls)),
]

# urlpatterns += router.urls
