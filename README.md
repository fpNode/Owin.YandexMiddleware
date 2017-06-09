YandexMiddleware
===================

mvc 5 owin module for yandex.ru

How to use?
-------------
1) Add nuget package - search for "fpNode.Owin.YandexMiddleware"
2) Add module in Startup.Auth.cs of your mvc 5 project

app.UseYandexAuthentication("{AppId}", "{AppSecret}");

How to register app in yandex.ru?
-------------
Info here https://tech.yandex.ru/oauth/doc/dg/tasks/register-client-docpage/

Live examples 
-------------
 https://farpoint-nn.ru/
