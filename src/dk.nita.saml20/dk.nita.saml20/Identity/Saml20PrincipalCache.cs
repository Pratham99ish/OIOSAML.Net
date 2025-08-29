using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using Identity.Saml.Session;
using Identity.Saml.identity;
using Identity.Saml.session;

namespace Identity.Saml.PrincipalCache
{
    /// <summary>
    /// 
    /// </summary>
    internal class Saml20PrincipalCache
    {
        /// <summary>
        /// Gets the principal.
        /// </summary>
        /// <returns></returns>
        internal static IPrincipal GetPrincipal()
        {
            var saml20Assertion = GetSaml20AssertionLite();
            if (saml20Assertion != null)
                return Saml20Identity.InitSaml20Identity(saml20Assertion);
            return null;
        }

        /// <summary>
        /// Gets the principal.
        /// </summary>
        /// <returns></returns>
        internal static Saml20AssertionLite GetSaml20AssertionLite()
        {
            return SessionStore.CurrentSession?[SessionConstants.Saml20AssertionLite] as Saml20AssertionLite;
        }
    }
}
