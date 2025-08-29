using System.Diagnostics;
using System.Web;
using System;
using System.Linq;
using Identity.Saml.config;
using Identity.Saml.Logging;
using Identity.Saml.Properties;
using Identity.Saml.protocol;
using Identity.Saml.Configuration;
using Identity.Saml.Session;
using Identity.Saml.Utils;
using Microsoft.AspNetCore.Http;

namespace Identity.Saml.Protocol
{
    /// <summary>
    /// Common Domain Cookie reader endpoint
    /// </summary>
    public class Saml20CDCReader
    {
        /// <summary>
        /// Processes the HTTP request for CDC reader endpoint.
        /// </summary>
        /// <param name="context">The HTTP context.</param>
        /// <param name="config">The SAML federation config options.</param>
        public void ProcessRequest(HttpContext context, SAML20FederationConfigOptions config)
        {
            try
            {
                // Find the signon endpoint from config
                var endp = config.ServiceProvider.ServiceEndpoints.FirstOrDefault(e => e.Type?.ToUpperInvariant() == "SIGNON");
                if (endp == null)
                    throw new Saml20Exception("Signon endpoint not found in configuration");

                string returnUrl = config.ServiceProvider.Server + endp.LocalPath + "?r=1";

                var cdcCookie = new CommonDomainCookie(context.Request.Cookies);
                if (cdcCookie.IsSet && !string.IsNullOrEmpty(cdcCookie.PreferredIDP))
                {
                    returnUrl += "&_saml_idp=" + HttpUtility.UrlEncode(cdcCookie.PreferredIDP);
                }
                context.Response.Redirect(returnUrl);
            }
            catch (Exception ex)
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                context.Response.WriteAsync($"{{\"error\":\"{ex.Message}\"}}");
            }
        }
    }
}
