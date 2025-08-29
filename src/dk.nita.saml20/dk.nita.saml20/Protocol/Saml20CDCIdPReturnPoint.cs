using System;
using System.Web;
using dk.nita.saml20.session;
using dk.nita.saml20.config;
using dk.nita.saml20.protocol;
using dk.nita.saml20.Session;
using dk.nita.saml20.Utils;
using dk.nita.saml20.Configuration;
using System.Linq;
using Microsoft.AspNetCore.Http;

namespace dk.nita.saml20.protocol
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
