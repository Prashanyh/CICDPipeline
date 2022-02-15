# Project Name :: XT-O1

# Commands 
Project creation
- django-admin startproject "XT-01"
- django-admin startapp "UserAdministriation"

# DataBase
creatinng tables & cloums use below commands, (adding single or more fields into the model use, "migrate command")
- after defining db Schema (models)
- python manage.py makemigrations
- python manage.py migrate

# Installations
install any Third party library (1) or avialable req list use (2) below commands
- pip install packagename
- pip list
- pip install -r requirements.txt


# Settings.py
add third party librarys ,apps  and Database changes,,,,,,
>DB settings

DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql_psycopg2',
            'NAME': '#',
            'USER': '#',
            'PASSWORD': '#',
            'HOST': 'localhost',
            'PORT': '5432',
            'options':{
                'init_command':"SET sql_mode='STRICT_TRANS_TABLES'"
            }
        }
    }

 ![Example screenshot](imgage/db.png)

## Table of Contents
* [General Info](#general-information)
* [Technologies Used](#technologies-used)
* [Features](#features)
* [Setup](#setup)
* [Run Server](#RunServer-Commands)
* [Usage](#usage)
* [Project Status](#project-status)
* [Acknowledgements](#acknowledgements)
* [Git Commands](#gitcommands)


## General Information
- This is a UserManagement Application.
- This application contains diffrent roles
> What is the purpose of your project?
- working some domain and doing the work as per requirements. 



## Technologies Used
- Django -3.2.8
- djangorestframework -3.12.4
- python -3.6

## Features
List the ready features here:
- XT-01 UserManagement 1
- Developing End-Points(Api's)


## Screenshots
![Example screenshot](./img/screenshot.png)
<!-- If you have screenshots you'd like to share, include them here. -->


## Setup
What are the project requirements/dependencies? Where are they listed?
- check A requirements.txt.
- Where is it located? project or git

>Proceed to describe how to install 
clone project
- https://github.com/Prashanyh/XT-O1-UserManagement.git
- setup one's local environment 
- get started with the project.


## RunServer-Commands
How to run server  use below commands
- python manage.py runserver 
> below command you can use custom port 
> Feature it will change
- python manage.py runserver 9000


## Project Status
Project is: _in progress


To do:
- Develloping all End-Points 1
- Feature to be added 2


## Acknowledgements
- This project was based on Itop.

## gitcommands
Basic commands
- git clone "clone project url"
- git commit -m "add comments"
- git push 
> creating new branch
- git checkout -b "create your own branch"
- git checkout "branch name"  , switch to another branch
