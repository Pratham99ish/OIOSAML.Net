using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Identity.Saml.session;
using Identity.Saml.config;
using System.Xml;
using Identity.Saml.Logging;
using Identity.Saml.Session;
using Saml2.Properties;
using Trace = Identity.Saml.Utils.Trace;

namespace Identity.Saml.protocol
{
    /// <summary>
    /// A base class for all WebAPI endpoint controllers.
    /// </summary>
    public abstract class AbstractEndpointController : ControllerBase
    {
        protected string ErrorBehaviour { get; set; }
        protected string RedirectUrl { get; set; }

        // Replace all AuditLogging static usage with TraceAuditLogger instance
        private readonly IAuditLogger _auditLogger = new TraceAuditLogger();

        /// <summary>
        /// Displays an error page or returns an error response.
        /// </summary>
        protected IActionResult HandleError(string errorMessage, bool overrideConfigSetting = false, Func<string, Saml20Exception> exceptionCreatorFunc = null)
        {
            Trace.TraceData(TraceEventType.Error, "Error: " + errorMessage);
            var showError = false; // Replace with config if needed
            const string defaultMessage = "Unable to validate SAML message!";

            if (!string.IsNullOrEmpty(ErrorBehaviour) && ErrorBehaviour.Equals("THROWEXCEPTION", StringComparison.OrdinalIgnoreCase))
            {
                var exception = showError ? exceptionCreatorFunc?.Invoke(errorMessage) : exceptionCreatorFunc?.Invoke(defaultMessage);
                throw exception ?? new Saml20Exception(errorMessage);
            }
            else
            {
                // Return error as HTTP response
                return BadRequest(new { error = showError ? errorMessage : defaultMessage });
            }
        }

        protected IActionResult HandleLoaValidationError(string errorMessageTemplate, string sourceLoa, string requiredMinLoa, XmlElement assertionXml)
        {
            var loaErrorMessage = string.Format(errorMessageTemplate, sourceLoa, requiredMinLoa);
            _auditLogger.LogEntry(loaErrorMessage + " Assertion: " + assertionXml.OuterXml, null, null, null, null, null, "IN", "AUTHNREQUEST_POST");
            return HandleError(loaErrorMessage, exceptionCreatorFunc: m => new Saml20NsisLoaException(m));
        }

        protected IActionResult HandleError(string format, params string[] args)
        {
            var htmlEncodedArguments = args.Select(WebUtility.HtmlEncode).Cast<object>().ToArray();
            var errorMessage = string.Format(format, htmlEncodedArguments);
            return HandleError(errorMessage, exceptionCreatorFunc: m => new Saml20Exception(m));
        }

        protected IActionResult HandleError(string errorMessage)
        {
            return HandleError(errorMessage, exceptionCreatorFunc: m => new Saml20Exception(m));
        }

        protected IActionResult HandleError(string errorMessage, bool overrideConfigSetting)
        {
            return HandleError(errorMessage, overrideConfigSetting, m => new Saml20Exception(m));
        }

        protected IActionResult HandleError(string errorMessage, Func<string, Saml20Exception> exceptionCreatorFunc)
        {
            return HandleError(errorMessage, false, exceptionCreatorFunc);
        }

        protected IActionResult HandleError(Exception e)
        {
            if (e is ThreadAbortException)
                return Ok();
            StringBuilder sb = new StringBuilder(1000);
            while (e != null)
            {
                sb.AppendLine(e.ToString());
                e = e.InnerException;
            }
            return HandleError(sb.ToString());
        }

        /// <summary>
        /// Redirects the user.
        /// </summary>
        protected IActionResult DoRedirect()
        {
            var currentSession = SessionStore.CurrentSession;
            if (currentSession != null)
            {
                var redirectUrl = (string)currentSession[SessionConstants.RedirectUrl];
                if (!string.IsNullOrEmpty(redirectUrl))
                {
                    currentSession[SessionConstants.RedirectUrl] = null;
                    return Redirect(redirectUrl);
                }
            }
            // Use default redirect url
            return Redirect(string.IsNullOrEmpty(RedirectUrl) ? "~/" : RedirectUrl);
        }
    }
}
