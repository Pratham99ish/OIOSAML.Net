using System;
using dk.nita.saml20.config;
using dk.nita.saml20.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace dk.nita.saml20.AuthnRequestAppender
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