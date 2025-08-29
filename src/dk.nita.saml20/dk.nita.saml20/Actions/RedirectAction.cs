using Microsoft.AspNetCore.Http;
using Identity.Saml.Protocol;

namespace Identity.Saml.Actions
{
    /// <summary>
    /// Performs redirect after login and logout
    /// </summary>
    public class RedirectAction : IAction
    {
        /// <summary>
        /// Default action name
        /// </summary>
        public const string ACTION_NAME = "Redirect";

        /// <summary>
        /// Action performed during login.
        /// </summary>
        public void LoginAction(Saml20AbstractEndpointHandler handler, HttpContext context, Saml20Assertion assertion)
        {
            context.Response.Redirect("~/");
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
