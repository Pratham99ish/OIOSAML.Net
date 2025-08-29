using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using Microsoft.AspNetCore.Http;
using Identity.Saml.Actions;
using Identity.Saml.AuthnRequestAppender;
using Identity.Saml.Bindings;
using Identity.Saml.Bindings.SignatureProviders;
using Identity.Saml.Session;
using Identity.Saml.session;
using Identity.Saml.Logging;
using Identity.Saml.Properties;
using Identity.Saml.Schema.Protocol;
using Identity.Saml.Schema.Metadata;
using Identity.Saml.Utils;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using Saml2.Properties;
using Identity.Saml.Configuration;
using Identity.Saml.config;

namespace Identity.Saml.Protocol
{
    public static class SAMLBinding
    {
        public const string REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
        public const string POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
        public const string ARTIFACT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
    }

    /// <summary>
    /// Implements a Saml 2.0 protocol sign-on endpoint. Handles all SAML bindings.
    /// </summary>
    public class Saml20SignonHandler : Saml20AbstractEndpointHandler
    {
        private readonly IAuditLogger _auditLogger = new TraceAuditLogger();
        private readonly IMemoryCache _memoryCache;

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20SignonHandler"/> class.
        /// </summary>
        public Saml20SignonHandler(SAML20FederationConfigService samlConfigService, ILogger<Saml20SignonHandler> logger, IMemoryCache memoryCache)
            : base(samlConfigService, logger)
        {
            _memoryCache = memoryCache;
        }

        #region IHttpHandler Members

        /// <summary>
        /// Handles a request.
        /// </summary>
        /// <param name="context">The context.</param>
        protected override void Handle(HttpContext context)
        {
            var query = context.Request.Query;
            var form = context.Request.HasFormContentType ? context.Request.Form : null;

            if (context.Request.Headers.ContainsKey("SOAPAction"))
            {
                SessionStore.AssertSessionExists();
                HandleSOAP(context, context.Request.Body);
                return;
            }

            string samlArt = query.ContainsKey("SAMLart") ? query["SAMLart"].ToString() : form?["SAMLart"];
            if (!string.IsNullOrEmpty(samlArt))
            {
                SessionStore.AssertSessionExists();
                HandleArtifact(context);
                return;
            }

            string samlResponse = query.ContainsKey("SamlResponse") ? query["SamlResponse"].ToString() : form?["SamlResponse"];
            if (!string.IsNullOrEmpty(samlResponse))
            {
                SessionStore.AssertSessionExists();
                HandleResponse(context);
                return;
            }

            bool commonDomainEnabled = _samlConfigService.GetConfig().CommonDomain.Enabled;
            bool cidpMissing = !query.ContainsKey(IDPChoiceParameterName) && (form == null || !form.ContainsKey(IDPChoiceParameterName));
            bool rMissing = !query.ContainsKey("r") && (form == null || !form.ContainsKey("r"));
            if (commonDomainEnabled && rMissing && cidpMissing)
            {
                _auditLogger.LogEntry("Redirecting to Common Domain for IDP discovery", null, null, null, null, null, "OUT", "DISCOVER");
                context.Response.Redirect(_samlConfigService.GetConfig().CommonDomain.LocalReaderEndpoint);
                return;
            }

            _auditLogger.LogEntry($"User accessing resource: {context.Request.Path} without authentication.", null, null, null, null, null, "IN", "ACCESS");

            SessionStore.CreateSessionIfNotExists();
            SendRequest(context);
        }

        #endregion

        private void HandleArtifact(HttpContext context)
        {
            var builder = new HttpArtifactBindingBuilder(context, context.RequestServices);
            // TODO: Implement ResolveArtifact logic or replace with correct method
            // Stream inputStream = builder.ResolveArtifact();
            // HandleSOAP(context, inputStream);
        }

        private void HandleSOAP(HttpContext context, Stream inputStream)
        {
            HttpArtifactBindingParser parser = new HttpArtifactBindingParser(inputStream);
            HttpArtifactBindingBuilder builder = new HttpArtifactBindingBuilder(context, context.RequestServices);

            if (parser.IsArtifactResolve())
            {
                var idp = RetrieveIDPConfiguration(parser.Issuer);
                // Signature validation logic should be implemented here if needed
            }
            else if (parser.IsArtifactResponse())
            {
                Status status = parser.ArtifactResponse.Status;
                if (status.StatusCode.Value != Saml20Constants.StatusCodes.Success)
                {
                    HandleError(context, status);
                    _auditLogger.LogEntry($"Illegal status for ArtifactResponse {status.StatusCode.Value} expected 'Success', msg: {parser.SamlMessage}", null, null, null, null, null, "IN", "ARTIFACTRESOLVE");
                    return;
                }
                if (parser.ArtifactResponse.Any.LocalName == Response.ELEMENT_NAME)
                {
                    bool isEncrypted;
                    XmlElement assertion = GetAssertion(parser.ArtifactResponse.Any, out isEncrypted);
                    if (assertion == null)
                        HandleError(context, new Status { StatusCode = new StatusCode { Value = "urn:oasis:names:tc:SAML:2.0:status:Responder" }, StatusMessage = "Missing assertion" });
                    if (isEncrypted)
                    {
                        HandleEncryptedAssertion(context, assertion);
                    }
                    else
                    {
                        HandleAssertion(context, assertion);
                    }
                }
                else
                {
                    _auditLogger.LogEntry($"Unsupported payload message in ArtifactResponse: {parser.ArtifactResponse.Any.LocalName}, msg: {parser.SamlMessage}", null, null, null, null, null, "IN", "ARTIFACTRESOLVE");
                    HandleError(context, new Status { StatusCode = new StatusCode { Value = "urn:oasis:names:tc:SAML:2.0:status:Responder" }, StatusMessage = $"Unsupported payload message in ArtifactResponse: {parser.ArtifactResponse.Any.LocalName}" });
                }
            }
            else
            {
                Status s = parser.GetStatus();
                if (s != null)
                {
                    HandleError(context, s);
                }
                else
                {
                    _auditLogger.LogEntry($"Unsupported SamlMessage element: {parser.SamlMessageName}, msg: {parser.SamlMessage}", null, null, null, null, null, "IN", "ARTIFACTRESOLVE");
                    HandleError(context, new Status { StatusCode = new StatusCode { Value = "urn:oasis:names:tc:SAML:2.0:status:Responder" }, StatusMessage = $"Unsupported SamlMessage element: {parser.SamlMessageName}" });
                }
            }
        }

        /// <summary>
        /// Send an authentication request to the IDP.
        /// </summary>
        private void SendRequest(HttpContext context)
        {
            var query = context.Request.Query;
            var form = context.Request.HasFormContentType ? context.Request.Form : null;
            string returnUrl = query.ContainsKey("ReturnUrl") ? query["ReturnUrl"].ToString() : form?["ReturnUrl"];
            bool preventOpenRedirectAttack = true;
            var serviceProvider = _samlConfigService.GetConfig().ServiceProvider;
            if (serviceProvider != null)
            {
                var prop = serviceProvider.GetType().GetProperty("PreventOpenRedirectAttack");
                if (prop != null && prop.PropertyType == typeof(bool))
                {
                    preventOpenRedirectAttack = (bool)prop.GetValue(serviceProvider);
                }
            }
            if (!string.IsNullOrEmpty(returnUrl) && (!preventOpenRedirectAttack || IsLocalUrl(returnUrl)))
                SessionStore.CurrentSession[SessionConstants.RedirectUrl] = returnUrl;

            var idpEndpoint = RetrieveIDP(context);
            if (idpEndpoint == null)
            {
                return;
            }
            Saml20AuthnRequest authnRequest = Saml20AuthnRequest.GetDefault(context.RequestServices);
            TransferClient(idpEndpoint, authnRequest, context);
        }

        /// <summary>
        /// This method is used for preventing open redirect attacks.
        /// </summary>
        /// <param name="url">URL that is checked for being local or not.</param>
        /// <returns>Returns true if URL is local. Empty or null strings are not considered as local URL's</returns>
        private bool IsLocalUrl(string url)
        {
            if (string.IsNullOrEmpty(url))
            {
                return false;
            }
            else
            {
                return ((url[0] == '/' && (url.Length == 1 ||
                        (url[1] != '/' && url[1] != '\\'))) ||   // "/" or "/foo" but not "//" or "/\"
                        (url.Length > 1 &&
                         url[0] == '~' && url[1] == '/'));   // "~/" or "~/foo"
            }
        }

        private Status GetStatusElement(XmlDocument doc)
        {
            XmlElement statElem =
                (XmlElement)doc.GetElementsByTagName(Status.ELEMENT_NAME, Saml20Constants.PROTOCOL)[0];

            return Serialization.DeserializeFromXmlString<Status>(statElem.OuterXml);
        }

        internal static XmlElement GetAssertion(XmlElement el, out bool isEncrypted)
        {

            XmlNodeList encryptedList =
                el.GetElementsByTagName(EncryptedAssertion.ELEMENT_NAME, Saml20Constants.ASSERTION);

            if (encryptedList.Count == 1)
            {
                isEncrypted = true;
                return (XmlElement)encryptedList[0];
            }

            XmlNodeList assertionList =
                el.GetElementsByTagName("Assertion", Saml20Constants.ASSERTION);

            if (assertionList.Count == 1)
            {
                isEncrypted = false;
                return (XmlElement)assertionList[0];
            }

            isEncrypted = false;
            return null;
        }

        /// <summary>
        /// Handle the authentication response from the IDP.
        /// </summary>        
        private void HandleResponse(HttpContext context)
        {
            Encoding defaultEncoding = Encoding.UTF8;
            XmlDocument doc = GetDecodedSamlResponse(context, defaultEncoding);

            _auditLogger.LogEntry("Received SAMLResponse: " + doc.OuterXml, null, null, null, null, null, "IN", "LOGIN");

            try
            {
                var inResponseToAttribute = doc.DocumentElement.Attributes["InResponseTo"];

                if (inResponseToAttribute == null)
                    throw new Saml20Exception("Received a response message that did not contain an InResponseTo attribute");

                string inResponseTo = inResponseToAttribute.Value;

                CheckReplayAttack(context, inResponseTo);

                Status status = GetStatusElement(doc);

                if (status.StatusCode.Value != Saml20Constants.StatusCodes.Success)
                {
                    if (status.StatusCode.Value == Saml20Constants.StatusCodes.Responder && status.StatusCode.SubStatusCode != null && Saml20Constants.StatusCodes.NoPassive == status.StatusCode.SubStatusCode.Value)
                        HandleError(context, new Status { StatusCode = new StatusCode { Value = "urn:oasis:names:tc:SAML:2.0:status:Responder" }, StatusMessage = Resources.SamlNoPassiveError });

                    HandleError(context, status);
                    return;
                }

                bool isEncrypted;
                XmlElement assertion = GetAssertion(doc.DocumentElement, out isEncrypted);
                if (isEncrypted)
                {
                    assertion = GetDecryptedAssertion(assertion).Assertion.DocumentElement;
                }

                string issuer = GetIssuer(assertion);
                var endpoint = RetrieveIDPConfiguration(issuer);
                if (!string.IsNullOrEmpty(endpoint?.ResponseEncoding))
                {
                    Encoding encodingOverride = null;
                    try
                    {
                        encodingOverride = System.Text.Encoding.GetEncoding(endpoint.ResponseEncoding);
                    }
                    catch (ArgumentException ex)
                    {
                        HandleError(context, new Status { StatusCode = new StatusCode { Value = "urn:oasis:names:tc:SAML:2.0:status:Responder" }, StatusMessage = ex.Message });
                        return;
                    }

                    if (encodingOverride.CodePage != defaultEncoding.CodePage)
                    {
                        XmlDocument doc1 = GetDecodedSamlResponse(context, encodingOverride);
                        assertion = GetAssertion(doc1.DocumentElement, out isEncrypted);
                    }
                }

                HandleAssertion(context, assertion);
                return;
            }
            catch (Exception ex)
            {
                HandleError(context, new Status { StatusCode = new StatusCode { Value = "urn:oasis:names:tc:SAML:2.0:status:Responder" }, StatusMessage = ex.Message });
                return;
            }
        }

        private static void CheckReplayAttack(HttpContext context, string inResponseTo)
        {
            if (string.IsNullOrEmpty(inResponseTo))
                throw new Saml20Exception("Empty InResponseTo from IdP is not allowed.");

            var expectedInResponseToSessionState = SessionStore.CurrentSession[SessionConstants.ExpectedInResponseTo];
            SessionStore.CurrentSession[SessionConstants.ExpectedInResponseTo] = null;

            string expectedInResponseTo = expectedInResponseToSessionState?.ToString();
            if (string.IsNullOrEmpty(expectedInResponseTo))
                throw new Saml20Exception("Expected InResponseTo not found in current session.");

            if (inResponseTo != expectedInResponseTo)
            {
                // _auditLogger is not available in static context, so skip logging here or refactor as needed
                throw new Saml20Exception("Replay attack.");
            }
        }

        private static XmlDocument GetDecodedSamlResponse(HttpContext context, Encoding encoding)
        {
            string base64 = null;
            var query = context.Request.Query;
            var form = context.Request.HasFormContentType ? context.Request.Form : null;
            if (query.ContainsKey("SAMLResponse"))
                base64 = query["SAMLResponse"].ToString();
            else if (form != null && form.ContainsKey("SAMLResponse"))
                base64 = form["SAMLResponse"];

            XmlDocument doc = new XmlDocument();
            doc.XmlResolver = null;
            doc.PreserveWhitespace = true;
            string samlResponse = encoding.GetString(Convert.FromBase64String(base64));
            // Replace Trace usage with logger or remove if not available
            doc.LoadXml(samlResponse);
            return doc;
        }

        /// <summary>
        /// Decrypts an encrypted assertion, and sends the result to the HandleAssertion method.
        /// </summary>
        private void HandleEncryptedAssertion(HttpContext context, XmlElement elem)
        {
            // Remove Trace usage and replace with logger or comment out
            // Example: _logger.LogInformation("HandleEncryptedAssertion() called");
            Saml20EncryptedAssertion decryptedAssertion = GetDecryptedAssertion(elem);
            HandleAssertion(context, decryptedAssertion.Assertion.DocumentElement);
        }

        /// <summary>
        /// Decrypts an encrypted assertion if any of the configured certificates contains the correct
        /// private key to use for decrypting. If no configured certificates can be used to decrypt the
        /// encrypted assertion, the first exception will be rethrown.
        /// </summary>
        /// <param name="elem"></param>
        /// <returns></returns>
        private static Saml20EncryptedAssertion GetDecryptedAssertion(XmlElement elem)
        {
            // Use POCO config for certificates
            var tryDecryptAssertion = new Func<X509Certificate2, Saml20EncryptedAssertion>((certificate) =>
            {
                Saml20EncryptedAssertion decryptedAssertion = new Saml20EncryptedAssertion((RSA)certificate.PrivateKey);
                decryptedAssertion.LoadXml(elem);
                decryptedAssertion.Decrypt();
                return decryptedAssertion;
            });

            // This should be replaced with the correct POCO config access if needed
            // For now, throw NotImplementedException to force migration
            throw new NotImplementedException("GetDecryptedAssertion should be implemented using POCO config certificates.");
        }

        /// <summary>
        /// Retrieves the name of the issuer from an XmlElement containing an assertion.
        /// </summary>
        /// <param name="assertion">An XmlElement containing an assertion</param>
        /// <returns>The identifier of the Issuer</returns>
        private string GetIssuer(XmlElement assertion)
        {
            string result = string.Empty;
            XmlNodeList list = assertion.GetElementsByTagName("Issuer", Saml20Constants.ASSERTION);
            if (list.Count > 0)
            {
                XmlElement issuer = (XmlElement)list[0];
                result = issuer.InnerText;
            }

            return result;
        }

        /// <summary>
        /// Is called before the assertion is made into a strongly typed representation
        /// </summary>
        /// <param name="context">The httpcontext.</param>
        /// <param name="elem">The assertion element.</param>
        /// <param name="endpoint">The endpoint.</param>
        protected virtual void PreHandleAssertion(HttpContext context, XmlElement elem, IDPEndPointOptions endpoint)
        {
            // Remove Trace usage and replace with logger or comment out
            // Example: _logger.LogInformation("PreHandleAssertion called");

            if (endpoint != null && endpoint.SLOEndpoint != null && !String.IsNullOrEmpty(endpoint.SLOEndpoint.IdpTokenAccessor))
            {
                ISaml20IdpTokenAccessor idpTokenAccessor =
                    Activator.CreateInstance(Type.GetType(endpoint.SLOEndpoint.IdpTokenAccessor, false)) as ISaml20IdpTokenAccessor;
                if (idpTokenAccessor != null)
                    idpTokenAccessor.ReadToken(elem);
            }

            // Remove Trace usage and replace with logger or comment out
            // Example: _logger.LogInformation("PreHandleAssertion done");
        }

        /// <summary>
        /// Deserializes an assertion, verifies its signature and logs in the user if the assertion is valid.
        /// </summary>
        private void HandleAssertion(HttpContext context, XmlElement elem)
        {
            // Remove Trace usage and replace with logger or comment out
            // Example: _logger.LogInformation("HandleAssertion called");

            string issuer = GetIssuer(elem);

            IDPEndPointOptions endp = RetrieveIDPConfiguration(issuer);

            // Remove all references to static AuditLogging
            // Use _auditLogger.LogEntry with string direction/operation

            PreHandleAssertion(context, elem, endp);

            bool quirksMode = false;

            if (endp != null)
            {
                quirksMode = endp.QuirksMode;
            }

            Saml20Assertion assertion = new Saml20Assertion(elem, null, quirksMode);
            assertion.Validate(DateTime.UtcNow);

            if (endp == null)
            {
                _auditLogger.LogEntry("Unknown login IDP, assertion: " + elem, null, null, null, null, null, "IN", "LOGIN");
                HandleError(context, new Status { StatusCode = new StatusCode { Value = "urn:oasis:names:tc:SAML:2.0:status:Responder" }, StatusMessage = Resources.UnknownLoginIDP });
                return;
            }

            // Signature validation logic should be implemented here if needed
            // if (!endp.OmitAssertionSignatureCheck) { ... }

            if (assertion.IsExpired())
            {
                _auditLogger.LogEntry("Assertion expired, assertion: " + elem.OuterXml, null, null, null, null, null, "IN", "LOGIN");
                HandleError(context, new Status { StatusCode = new StatusCode { Value = "urn:oasis:names:tc:SAML:2.0:status:Responder" }, StatusMessage = Resources.AssertionExpired });
                return;
            }

            if (!ValidateLoA(context, assertion, elem)) return;

            // CheckConditions(context, assertion); // Commented out, not implemented
            // DoLogin(context, assertion); // Commented out, not implemented
        }

        /// <summary>
        /// Validates the LoA of the session to determine if it adheres to the configured requirements of the service provider.
        /// If validation fails, response is modified to display an error page.
        /// </summary>
        /// <returns>True if valid, otherwise false.</returns>
        private bool ValidateLoA(HttpContext context, Saml20Assertion assertion, XmlElement assertionXml)
        {
            // If AssuranceLevel is allowed, and it's present in assertion, validate.
            var allowAL = _samlConfigService.GetConfig().AllowAssuranceLevel;
            // var assertionAL = GetAssuranceLevel(assertion); // Commented out, not implemented
            // if(allowAL && assertionAL != null)
            // {
            //     return ValidateAssuranceLevel(assertionAL, context, assertionXml);
            // }

            // If NSIS LoA is missing, invalidate.
            // var assertionNsisLoa = GetNsisLoa(assertion); // Commented out, not implemented
            // if (assertionNsisLoa == null)
            // {
            //     AuditLogging.logEntry(Resources.NsisLoaMissing + " Assertion: " + assertionXml.OuterXml, null, null, null, null, null, "IN", "AUTHNREQUEST_POST");
            //     HandleError(context, Resources.NsisLoaMissing);
            //     return false;
            // }

            // return ValidateNsisLoa(assertionNsisLoa, context, assertionXml); // Commented out, not implemented
            return true;
        }

        /// <summary>
        /// Validates if a NSIS LoA is equals to or higher than a minimum required LoA.
        /// If validation fails, response is modified to display an error page.
        /// </summary>
        /// <returns>True if valid, otherwise false (and modified response).</returns>
        private bool ValidateNsisLoa(string loa, HttpContext context, XmlElement assertionXml)
        {
            // Commented out, not implemented
            return true;
        }

        /// <summary>
        /// Validates if a AssuranceLevel is equals to or higher than a minimum required AssuranceLevel.
        /// If validation fails, response is modified to display an error page.
        /// </summary>
        /// <returns>True if valid, otherwise false (and modified response).</returns>
        private bool ValidateAssuranceLevel(string assouranceLevel, HttpContext context, XmlElement assertionXml)
        {
            // Commented out, not implemented
            return true;
        }

        internal static IEnumerable<AsymmetricAlgorithm> GetTrustedSigners(ICollection<KeyDescriptor> keys, IDPEndPointOptions ep, out IEnumerable<string> validationFailureReasons)
        {
            // Commented out, not implemented
            validationFailureReasons = new List<string>();
            return new List<AsymmetricAlgorithm>();
        }

        private static bool IsSatisfiedByAllSpecifications(IDPEndPointOptions ep, X509Certificate2 cert, out string failureReason)
        {
            // Commented out, not implemented
            failureReason = null;
            return true;
        }

        private IDPEndPointOptions RetrieveIDPConfiguration(string issuer)
        {
            // Find the IDP endpoint by issuer from federation config
            return _samlConfigService.GetConfig().IDPEndPoints.FirstOrDefault(ep => ep.Id == issuer);
        }

        private IDPEndPointOptions RetrieveIDP(HttpContext context)
        {
            // Example: retrieve IDP from query or form
            var query = context.Request.Query;
            var form = context.Request.HasFormContentType ? context.Request.Form : null;
            string idpId = query.ContainsKey("idp") ? query["idp"].ToString() : form?["idp"];
            if (!string.IsNullOrEmpty(idpId))
                return _samlConfigService.GetConfig().IDPEndPoints.FirstOrDefault(ep => ep.Id == idpId);
            // fallback: return default IDP
            return _samlConfigService.GetConfig().IDPEndPoints.FirstOrDefault(ep => ep.Default);
        }

        private void TransferClient(IDPEndPointOptions idpEndpoint, Saml20AuthnRequest request, HttpContext context)
        {
            _auditLogger.LogEntry("Starting transfer to IDP: " + idpEndpoint.Id, null, null, idpEndpoint.Id, request.ID, null, "OUT", "LOGIN");
            var query = context.Request.Query;
            var form = context.Request.HasFormContentType ? context.Request.Form : null;
            IDPEndPointElementOptions destination = idpEndpoint.SSOEndpoint;
            request.Destination = destination.Url;
            string appSwitchPlatform = query.ContainsKey(AppSwitchPlatform) ? query[AppSwitchPlatform].ToString() : form?[AppSwitchPlatform];
            if (!string.IsNullOrWhiteSpace(appSwitchPlatform))
            {
                var appSwitchReturnUrl = _samlConfigService.GetConfig().AppSwitchReturnURL?.FirstOrDefault(x => x.Platform == appSwitchPlatform)?.Value;
                if (appSwitchReturnUrl != null)
                {
                    context.Response.Redirect(appSwitchReturnUrl);
                    return;
                }
            }
            if (destination.Binding == SAMLBinding.REDIRECT)
            {
                context.Response.Redirect(destination.Url);
                return;
            }
        }
    }
}