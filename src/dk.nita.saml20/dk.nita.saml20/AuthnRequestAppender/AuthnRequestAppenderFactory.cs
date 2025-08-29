using System;
using Identity.Saml.config;
using Identity.Saml.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Identity.Saml.AuthnRequestAppender
{
    /// <summary>
    /// IAuthnRequestAppender Factory
    /// </summary>
    public static class AuthnRequestAppenderFactory
    {
        /// <summary>
        /// Get appender if configured
        /// </summary>
        /// <returns></returns>
        public static IAuthnRequestAppender GetAppender(IServiceProvider serviceProvider)
        {
            var configService = serviceProvider.GetRequiredService<FederationConfigService>();
            var config = configService.GetConfig();
            if (string.IsNullOrEmpty(config.AuthnRequestAppender?.Type))
            {
                return null;
            }
            return (IAuthnRequestAppender)Activator.CreateInstance(Type.GetType(config.AuthnRequestAppender.Type));
        } 
    }
}