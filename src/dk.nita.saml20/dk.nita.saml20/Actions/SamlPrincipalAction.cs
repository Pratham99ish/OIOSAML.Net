using Microsoft.AspNetCore.Http;
using System.Security.Principal;
using System.Security.Claims;
using Identity.Saml.Session;
using Identity.Saml.PrincipalCache;
using Identity.Saml.Protocol;

namespace Identity.Saml.Actions
{
    /// <summary>
    /// Sets the SamlPrincipal on the current http context
    /// </summary>
    public class SamlPrincipalAction : IAction
    {
        /// <summary>
        /// The default action name
        /// </summary>
        public const string ACTION_NAME = "SetSamlPrincipal";

        /// <summary>
        /// Action performed during login.
        /// </summary>
        public void LoginAction(Saml20AbstractEndpointHandler handler, HttpContext context, Saml20Assertion assertion)
        {
            // Convert IPrincipal to ClaimsPrincipal if possible
            var principal = Saml20PrincipalCache.GetPrincipal();
            if (principal is ClaimsPrincipal claimsPrincipal)
                context.User = claimsPrincipal;
            else
                context.User = new ClaimsPrincipal(new ClaimsIdentity(principal.Identity));
        }

        /// <summary>
        /// Action performed during logout.
        /// </summary>
        public void LogoutAction(Saml20AbstractEndpointHandler handler, HttpContext context, bool IdPInitiated)
        {
            context.User = new ClaimsPrincipal(new ClaimsIdentity(string.Empty));
        }

        /// <summary>
        /// <see cref="IAction.SoapLogoutAction"/>
        /// </summary>
        public void SoapLogoutAction(Saml20AbstractEndpointHandler handler, HttpContext context, string userId)
        {
            // Do nothing
        }

        private string _name;

        /// <summary>
        /// Gets or sets the name of the action.
        /// </summary>
        /// <value>The name.</value>
        public string Name
        {
            get { return string.IsNullOrEmpty(_name) ? ACTION_NAME : _name; }
            set { _name = value; }
        }
    }
}
