using System;
using System.Web;
using Identity.Saml.session;
using Identity.Saml.config;
using Identity.Saml.protocol;
using Identity.Saml.Session;
using Identity.Saml.Utils;
using Identity.Saml.Configuration;
using System.Linq;
using Microsoft.AspNetCore.Http;

namespace Identity.Saml.Protocol
{
    /// <summary>
    /// Handles the return point for Common Domain Cookie IDP selection.
    /// </summary>
    public class Saml20CDCIdPReturnPoint
    {
        /// <summary>
        /// Processes the HTTP request for CDC return point.
        /// </summary>
        /// <param name="context">The HTTP context.</param>
        public void ProcessRequest(HttpContext context, SAML20FederationConfigOptions config)
        {
            try
            {
                // Find the signon endpoint from config
                var endp = config.ServiceProvider.ServiceEndpoints.FirstOrDefault(e => e.Type?.ToUpperInvariant() == "SIGNON");
                if (endp == null)
                    throw new Saml20Exception("Signon endpoint not found in configuration");

                string redirectUrl = (string)SessionStore.CurrentSession?[SessionConstants.RedirectUrl];
                if (!string.IsNullOrEmpty(redirectUrl))
                {
                    SessionStore.CurrentSession[SessionConstants.RedirectUrl] = null;
                    context.Response.Redirect(redirectUrl);
                }
                else if (string.IsNullOrEmpty(endp.RedirectUrl))
                {
                    context.Response.Redirect("~/");
                }
                else
                {
                    context.Response.Redirect(endp.RedirectUrl);
                }
            }
            catch (Exception ex)
            {
                // Basic error handling: set status code and write error
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                context.Response.WriteAsync($"{{\"error\":\"{ex.Message}\"}}");
            }
        }
    }
}
