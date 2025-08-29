using System;
using System.Text;

namespace dk.nita.saml20.Bindings
{
    /// <summary>
    /// Modern implementation of the HTTP POST binding for API use.
    /// </summary>
    public class HttpPostBindingBuilder
    {
        public string PostUrl { get; }
        public string RelayState { get; set; }
        public string SAMLRequest { get; set; }
        public string SAMLResponse { get; set; }

        public HttpPostBindingBuilder(string postUrl)
        {
            PostUrl = postUrl;
        }

        /// <summary>
        /// Generates the HTML form for SAML POST binding.
        /// </summary>
        /// <returns>HTML string for the form.</returns>
        public string GetHtmlForm()
        {
            var sb = new StringBuilder();
            sb.AppendLine("<form method='post' action='" + PostUrl + "'>");
            if (!string.IsNullOrEmpty(SAMLRequest))
                sb.AppendLine($"<input type='hidden' name='SAMLRequest' value='{System.Net.WebUtility.HtmlEncode(SAMLRequest)}' />");
            if (!string.IsNullOrEmpty(SAMLResponse))
                sb.AppendLine($"<input type='hidden' name='SAMLResponse' value='{System.Net.WebUtility.HtmlEncode(SAMLResponse)}' />");
            if (!string.IsNullOrEmpty(RelayState))
                sb.AppendLine($"<input type='hidden' name='RelayState' value='{System.Net.WebUtility.HtmlEncode(RelayState)}' />");
            sb.AppendLine("<noscript><input type='submit' value='Continue' /></noscript>");
            sb.AppendLine("</form>");
            sb.AppendLine("<script>document.forms[0].submit();</script>");
            return sb.ToString();
        }
    }
}