using System;
using fpNode.Owin.YandexMiddleware;
using Microsoft.Owin.Security;

namespace Owin
{
    /// <summary>
    /// Extension methods for using <see cref="YandexAuthenticationMiddleware"/>
    /// </summary>
    public static class YandexAuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users using Yandex
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseYandexAuthentication(this IAppBuilder app, YandexAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(YandexAuthenticationMiddleware), app, options);
            return app;
        }

        /// <summary>
        /// Authenticate users using Yandex
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="appId">The appId assigned by Yandex</param>
        /// <param name="appSecret">The appSecret assigned by Yandex</param>
        /// <param name="scope">The permissions list. Comma separated. Like "audio,video,photos"</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseYandexAuthentication(
            this IAppBuilder app,
            string appId,
            string appSecret)
        {
            return UseYandexAuthentication(
                app,
                new YandexAuthenticationOptions
                {
                    AppId = appId,
                    AppSecret = appSecret
                });
        }
    }
}
