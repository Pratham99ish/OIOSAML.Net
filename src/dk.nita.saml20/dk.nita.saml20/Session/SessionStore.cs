using System;
using dk.nita.saml20.config;
using dk.nita.saml20.Utils;
using Microsoft.AspNetCore.Http;

namespace dk.nita.saml20.Session
{
    internal static class SessionStore
    {
        static ISessionStoreProvider SessionStoreProvider;
        static IHttpContextAccessor _httpContextAccessor;
        static TimeSpan _sessionTimeout;

        public static void Initialize(ISessionStoreProvider provider, IHttpContextAccessor httpContextAccessor, TimeSpan sessionTimeout)
        {
            SessionStoreProvider = provider;
            _httpContextAccessor = httpContextAccessor;
            _sessionTimeout = sessionTimeout;
        }

        internal static UserSession CurrentSession
        {
            get
            {
                var context = _httpContextAccessor?.HttpContext;
                if (context != null)
                {
                    var sessionId = GetSessionIdFromCookie(context);
                    if (sessionId.HasValue)
                    {
                        return new UserSession(SessionStoreProvider, sessionId.Value);
                    }
                }
                return null;
            }
        }

        internal static void CreateSessionIfNotExists()
        {
            var context = _httpContextAccessor?.HttpContext;
            if (context == null)
            {
                throw new InvalidOperationException("A session cannot be created when running outside the context of an ASP.NET Core request");
            }
            var sessionId = GetSessionIdFromCookie(context);
            if (!sessionId.HasValue)
            {
                WriteSessionCookie(context);
            }
        }

        internal static void AssociateUserIdWithCurrentSession(string userId)
        {
            if (userId == null) throw new ArgumentNullException(nameof(userId));
            SessionStoreProvider.AssociateUserIdWithSessionId(userId.ToLowerInvariant(), CurrentSession.SessionId);
        }

        internal static void AbandonAllSessions(string userId)
        {
            if (userId == null) throw new ArgumentNullException(nameof(userId));
            SessionStoreProvider.AbandonSessionsAssociatedWithUserId(userId.ToLowerInvariant());
        }

        private static Guid? GetSessionIdFromCookie(HttpContext context)
        {
            var cookie = context.Request.Cookies[GetSessionCookieName()];
            if (!string.IsNullOrEmpty(cookie))
                return new Guid(cookie);
            return null;
        }

        private static void WriteSessionCookie(HttpContext context)
        {
            var sessionId = Guid.NewGuid();
            var cookieOptions = new CookieOptions
            {
                Secure = true,
                HttpOnly = true,
                SameSite = SameSiteMode.None
            };
            context.Response.Cookies.Append(GetSessionCookieName(), sessionId.ToString(), cookieOptions);
        }

        private static string GetSessionCookieName()
        {
            // You should inject config or use DI here
            return "SamlSessionId";
        }

        internal static void AssertSessionExists()
        {
            if (!DoesSessionExists())
            {
                if (CurrentSession == null)
                {
                    throw new Saml20Exception(
                        "The user doesn't have a session in context of a cookie ... which is required at this point in the pipeline. Plausible reason is that OIOSAML.Net is not running under https. The session cookie is marked with 'secure only'.");
                }
                else if (!SessionStoreProvider.DoesSessionExists(CurrentSession.SessionId))
                {
                    throw new Saml20Exception(
                        "The user doesn't have a session in session store which is required at this point in the pipeline. Plausible reason is that the user's session has expired. \nIf the application is running in a web farm ensure distributed sessions is supported by the session store provider.");
                }
                else
                {
                    throw new Saml20Exception("The user doesn't have a session for unknown reasons.");
                }
            }
        }

        internal static bool DoesSessionExists()
        {
            return CurrentSession != null && SessionStoreProvider.DoesSessionExists(CurrentSession.SessionId);
        }
    }
}