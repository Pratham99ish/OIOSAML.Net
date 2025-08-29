using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using Identity.Saml;
using Identity.Saml.PrincipalCache;
using Identity.Saml.Session;
using Identity.Saml.Configuration;
using Identity.Saml.Protocol;

namespace Identity.Saml.Actions
{
    /// <summary>
    /// This action redirects to a Common Domain Cookie writer endpoint at the IdP.
    /// </summary>
    public class CDCRedirectAction : IAction
    {
        public const string IDPCookieWriterEndPoint = "IDPCookieWriterEndPoint";
        public const string LocalReturnUrl = "LocalReturnUrl";
        public const string TargetResource = "TargetResource";

        /// <summary>
        /// Action performed during login.
        /// </summary>
        public void LoginAction(Saml20AbstractEndpointHandler handler, HttpContext context, Saml20Assertion assertion)
        {
            string idpKey = Saml20PrincipalCache.GetSaml20AssertionLite().Issuer;
            var h = handler as Saml20SignonHandler;
            if (h == null)
                throw new Saml20Exception("Handler is not a Saml20SignonHandler");
            var ep = h.RetrieveIDPConfiguration(idpKey); // IDPEndPointOptions
            if (ep?.CDC?.ExtraSettings?.KeyValues != null)
            {
                List<KeyValueOptions> values = ep.CDC.ExtraSettings.KeyValues;

                var idpEndpoint = values.Find(kv => kv.Key == IDPCookieWriterEndPoint);
                if (idpEndpoint == null)
                    throw new Saml20Exception($"Please specify '{IDPCookieWriterEndPoint}' in Settings element.");

                var localReturnPoint = values.Find(kv => kv.Key == LocalReturnUrl);
                if (localReturnPoint == null)
                    throw new Saml20Exception($"Please specify '{LocalReturnUrl}' in Settings element.");

                string url = idpEndpoint.Value + "?" + TargetResource + "=" + localReturnPoint.Value;
                context.Response.Redirect(url);
            }
            else
            {
                context.Response.Redirect("~/");
            }
        }

        /// <summary>
        /// Action performed during logout.
        /// </summary>
        public void LogoutAction(Saml20AbstractEndpointHandler handler, HttpContext context, bool IdPInitiated)
        {
            if (!IdPInitiated)
                context.Response.Redirect("~/");
        }

        /// <summary>
        /// <see cref="IAction.SoapLogoutAction"/>
        /// </summary>
        public void SoapLogoutAction(Saml20AbstractEndpointHandler handler, HttpContext context, string userId)
        {
            // Do nothing
        }

        private string _name = "CDCRedirectAction";

        /// <summary>
        /// Gets or sets the name of the action.
        /// </summary>
        public string Name
        {
            get { return _name; }
            set { _name = value; }
        }
    }
}
