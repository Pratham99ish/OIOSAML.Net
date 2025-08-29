using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Linq;
using System.Xml;
using Identity.Saml.Bindings;
using Identity.Saml.Session;
using Identity.Saml.Schema.Metadata;
using Identity.Saml.Schema.Protocol;
using Identity.Saml.Utils;
using Microsoft.AspNetCore.Http;
using Identity.Saml.Configuration;
using Identity.Saml.Actions;
using Trace = Identity.Saml.Utils.Trace;
using Identity.Saml.config;

namespace Identity.Saml.Protocol
{
    /// <summary>
    /// Handles logout for all SAML bindings.
    /// </summary>
    public class Saml20LogoutHandler : Saml20AbstractEndpointHandler
    {
        public string RedirectUrl { get; set; }
        public string ErrorBehaviour { get; set; }

        public Saml20LogoutHandler(SAML20FederationConfigService samlConfigService, ILogger logger)
            : base(samlConfigService, logger)
        {
            var config = samlConfigService.GetConfig();
            RedirectUrl = config.ServiceProvider?.Id;
        }

        // Implements the required abstract method from Saml20AbstractEndpointHandler
        protected override void Handle(HttpContext context)
        {
            try
            {
                var request = context.Request;
                if (request.Headers.ContainsKey("SOAPAction"))
                {
                    HandleSOAP(context, request.Body);
                    return;
                }
                if (!string.IsNullOrEmpty(request.Query["SAMLart"]))
                {
                    HandleArtifact(context);
                    return;
                }
                if (!string.IsNullOrEmpty(request.Query["SAMLResponse"]))
                {
                    HandleResponse(context);
                }
                else if (!string.IsNullOrEmpty(request.Query["SAMLRequest"]))
                {
                    HandleRequest(context);
                }
                else
                {
                    IDPEndPointOptions idpEndpoint = null;
                    if (idpEndpoint == null)
                    {
                        context.Items["User"] = null;
                        HandleError(context, new Status { StatusCode = new StatusCode { Value = "urn:oasis:names:tc:SAML:2.0:status:Responder" } });
                    }
                    TransferClient(idpEndpoint, context);
                }
            }
            catch (Exception e)
            {
                if (e is ThreadAbortException)
                    throw;
                HandleError(context, new Status { StatusCode = new StatusCode { Value = "urn:oasis:names:tc:SAML:2.0:status:Responder" }, StatusMessage = e.Message });
            }
        }

        private void HandleArtifact(HttpContext context)
        {
            HttpArtifactBindingBuilder builder = new HttpArtifactBindingBuilder(context, context.RequestServices);
            // TODO: Replace with correct method to resolve artifact, if available
            Stream inputStream = null; // builder.ResolveArtifact();
            HandleSOAP(context, inputStream);
        }

        private void HandleSOAP(HttpContext context, Stream inputStream)
        {
            HttpArtifactBindingParser parser = new HttpArtifactBindingParser(inputStream);
            HttpArtifactBindingBuilder builder = new HttpArtifactBindingBuilder(context, context.RequestServices);
            var config = _samlConfigService.GetConfig();
            IDPEndPointOptions idp = RetrieveIDPConfiguration(parser.Issuer);
            Status errorStatus = new Status { StatusCode = new StatusCode { Value = "urn:oasis:names:tc:SAML:2.0:status:Responder" } };
            if (parser.IsArtifactResolve())
            {
                // TODO: Pass correct key collection for signature check
                if (!parser.CheckSamlMessageSignature(null))
                {
                    HandleError(context, errorStatus);
                    return;
                }
                // TODO: Implement correct response logic
            }
            else if (parser.IsArtifactResponse())
            {
                Status status = parser.ArtifactResponse.Status;
                if (status.StatusCode.Value != Saml20Constants.StatusCodes.Success)
                {
                    HandleError(context, status);
                    return;
                }
                if (parser.ArtifactResponse.Any.LocalName == LogoutRequest.ELEMENT_NAME)
                {
                    // TODO: Implement correct response logic
                }
                else if (parser.ArtifactResponse.Any.LocalName == LogoutResponse.ELEMENT_NAME)
                {
                    DoLogout(context, false);
                }
                else
                {
                    HandleError(context, errorStatus);
                }
            }
            else if (parser.IsLogoutReqest())
            {
                Status responseStatus = errorStatus;
                if (!parser.IsSigned())
                {
                    responseStatus = new Status { StatusCode = new StatusCode { Value = Saml20Constants.StatusCodes.RequestDenied } };
                }
                if (idp == null)
                {
                    responseStatus = new Status { StatusCode = new StatusCode { Value = Saml20Constants.StatusCodes.NoAvailableIDP } };
                }
                else
                {
                    ValidateNotOnOrAfter(context, parser.LogoutRequest);
                }
                if (parser.GetNameID() != null && !string.IsNullOrEmpty(parser.GetNameID().Value))
                    DoSoapLogout(context, parser.GetNameID().Value);
                else
                {
                    responseStatus = new Status { StatusCode = new StatusCode { Value = Saml20Constants.StatusCodes.NoAuthnContext } };
                }
                HandleError(context, responseStatus);
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
                    HandleError(context, errorStatus);
                }
            }
        }

        private void TransferClient(IDPEndPointOptions endpoint, HttpContext context)
        {
            var destination = endpoint.SLOEndpoint;
            Saml20LogoutRequest request = Saml20LogoutRequest.GetDefault(context.RequestServices);
            request.Destination = destination.Url;
            if (destination.Binding == SAMLBinding.POST)
            {
                string xml = request.GetXml().OuterXml;
                context.Response.ContentType = "text/xml";
                using (var writer = new StreamWriter(context.Response.Body))
                {
                    writer.Write(xml);
                }
                context.Response.Body.Close();
                return;
            }
            if (destination.Binding == SAMLBinding.REDIRECT)
            {
                HttpRedirectBindingBuilder builder = new HttpRedirectBindingBuilder();
                builder.Request = request.GetXml().OuterXml;
                string redirectUrl = destination.Url + "?" + builder.ToQuery();
                context.Response.Redirect(redirectUrl);
                return;
            }
            if (destination.Binding == SAMLBinding.ARTIFACT)
            {
                HttpArtifactBindingBuilder builder = new HttpArtifactBindingBuilder(context, context.RequestServices);
                builder.RedirectFromLogout(endpoint, destination, request, Guid.NewGuid().ToString("N"));
            }
            HandleError(context, new Status { StatusCode = new StatusCode { Value = "urn:oasis:names:tc:SAML:2.0:status:Responder" } });
        }

        private void HandleResponse(HttpContext context)
        {
            var config = _samlConfigService.GetConfig();
            var request = context.Request;
            string message = string.Empty;
            if (request.Method == "GET")
            {
                HttpRedirectBindingParser parser = new HttpRedirectBindingParser(new Uri(request.Path));
                LogoutResponse response = Serialization.DeserializeFromXmlString<LogoutResponse>(parser.Message);
                var endpoint = config.IDPEndPoints.FirstOrDefault(e => e.Id == response.Issuer.Value);
                if (endpoint == null)
                {
                    HandleError(context, new Status { StatusCode = new StatusCode { Value = "urn:oasis:names:tc:SAML:2.0:status:Responder" }, StatusMessage = $"Unknown IDP: {response.Issuer.Value}" });
                    return;
                }
                message = parser.Message;
            }
            else if (request.Method == "POST")
            {
                HttpPostBindingParser parser = new HttpPostBindingParser(context);
                LogoutResponse response = Serialization.DeserializeFromXmlString<LogoutResponse>(parser.Message);
                var endpoint = config.IDPEndPoints.FirstOrDefault(e => e.Id == response.Issuer.Value);
                if (endpoint == null)
                {
                    HandleError(context, new Status { StatusCode = new StatusCode { Value = "urn:oasis:names:tc:SAML:2.0:status:Responder" }, StatusMessage = $"Unknown IDP: {response.Issuer.Value}" });
                    return;
                }
                message = parser.Message;
            }
            else
            {
                HandleError(context, new Status { StatusCode = new StatusCode { Value = "urn:oasis:names:tc:SAML:2.0:status:Responder" }, StatusMessage = $"Unsupported request type: {request.Method}" });
                return;
            }
            XmlDocument doc = new XmlDocument();
            doc.XmlResolver = null;
            doc.PreserveWhitespace = true;
            doc.LoadXml(message);
            XmlElement statElem = (XmlElement)doc.GetElementsByTagName(Status.ELEMENT_NAME, Saml20Constants.PROTOCOL)[0];
            Status status = Serialization.DeserializeFromXmlString<Status>(statElem.OuterXml);
            if (status.StatusCode.Value != Saml20Constants.StatusCodes.Success)
            {
                HandleError(context, status);
                return;
            }
            DoLogout(context, false);
        }

        private void HandleRequest(HttpContext context)
        {
            var config = _samlConfigService.GetConfig();
            LogoutRequest logoutRequest = null;
            IDPEndPointOptions endpoint = null;
            string message = string.Empty;
            var response = new Saml20LogoutResponse();
            response.Issuer = config.ServiceProvider.Id;
            response.StatusCode = Saml20Constants.StatusCodes.Success;
            var request = context.Request;
            if (request.Method == "GET")
            {
                HttpRedirectBindingParser parser = new HttpRedirectBindingParser(new Uri(request.Path));
                if (!parser.IsSigned)
                {
                    response.StatusCode = Saml20Constants.StatusCodes.RequestDenied;
                }
                logoutRequest = parser.LogoutRequest;
                endpoint = config.IDPEndPoints.FirstOrDefault(e => e.Id == logoutRequest.Issuer.Value);
                if (endpoint == null)
                {
                    HandleError(context, new Status { StatusCode = new StatusCode { Value = "urn:oasis:names:tc:SAML:2.0:status:Responder" }, StatusMessage = $"Cannot find metadata for IdP {logoutRequest.Issuer.Value}" });
                    return;
                }
                ValidateNotOnOrAfter(context, logoutRequest);
                message = parser.Message;
            }
            else if (request.Method == "POST")
            {
                HttpPostBindingParser parser = new HttpPostBindingParser(context);
                if (!parser.IsSigned())
                {
                    response.StatusCode = Saml20Constants.StatusCodes.RequestDenied;
                }
                logoutRequest = parser.LogoutRequest;
                endpoint = config.IDPEndPoints.FirstOrDefault(e => e.Id == logoutRequest.Issuer.Value);
                if (endpoint == null)
                {
                    HandleError(context, new Status { StatusCode = new StatusCode { Value = "urn:oasis:names:tc:SAML:2.0:status:Responder" }, StatusMessage = $"Cannot find metadata for IdP {logoutRequest.Issuer.Value}" });
                    return;
                }
                ValidateNotOnOrAfter(context, logoutRequest);
                message = parser.Message;
            }
            else
            {
                HandleError(context, new Status { StatusCode = new StatusCode { Value = "urn:oasis:names:tc:SAML:2.0:status:Responder" }, StatusMessage = $"Unsupported request type: {request.Method}" });
                return;
            }
            // Remove session/identity logic
            // Build response and send using POST or REDIRECT
            var destination = endpoint.SLOEndpoint;
            response.Destination = destination.Url;
            response.InResponseTo = logoutRequest.ID;
            if (destination.Binding == SAMLBinding.REDIRECT)
            {
                HttpRedirectBindingBuilder builder = new HttpRedirectBindingBuilder();
                builder.Request = response.GetXml().OuterXml;
                string s = destination.Url + "?" + builder.ToQuery();
                context.Response.Redirect(s);
                return;
            }
            if (destination.Binding == SAMLBinding.POST)
            {
                string xml = response.GetXml().OuterXml;
                context.Response.ContentType = "text/xml";
                using (var writer = new StreamWriter(context.Response.Body))
                {
                    writer.Write(xml);
                }
                context.Response.Body.Close();
                return;
            }
        }

        private void ValidateNotOnOrAfter(HttpContext context, LogoutRequest logoutRequest)
        {
            if (!logoutRequest.NotOnOrAfter.HasValue)
            {
                return;
            }
            var notOnOrAfter = logoutRequest.NotOnOrAfter.Value;
            // Use default clock skew if not present
            var allowedClockSkewTime = 5; // minutes
            var now = DateTime.UtcNow;
            if (notOnOrAfter.AddMinutes(allowedClockSkewTime) > now)
            {
                return;
            }
            var errormessage = $"Logout request expired. NotOnOrAfter={notOnOrAfter}, RequestReceived={now}";
            HandleError(context, new Status { StatusCode = new StatusCode { Value = "urn:oasis:names:tc:SAML:2.0:status:Responder" }, StatusMessage = errormessage });
        }

        private FederationConfigOptions MapToFederationConfigOptions(SAML20FederationConfigOptions samlConfig)
        {
            // Only map properties that exist in both classes
            return new FederationConfigOptions
            {
                // No direct mapping for SigningCertificates, AudienceUris, Actions, AuthnRequestAppender
                AllowedClockSkewMinutes = 5 // Default value
            };
        }

        private void DoLogout(HttpContext context, bool IdPInitiated)
        {
            try
            {
                var config = _samlConfigService.GetConfig();
                var federationConfig = MapToFederationConfigOptions(config);
                foreach (var action in Actions.Actions.GetActions(federationConfig))
                {
                    Trace.TraceMethodCalled(action.GetType(), "LogoutAction()");
                    action.LogoutAction(this, context, IdPInitiated);
                    Trace.TraceMethodDone(action.GetType(), "LogoutAction()");
                }
            }
            finally
            {
                if (SessionStore.CurrentSession != null)
                {
                    Trace.TraceData(TraceEventType.Information, "Clearing session for userId");
                    SessionStore.AbandonAllSessions("");
                    Trace.TraceData(TraceEventType.Verbose, "Session cleared.");
                }
                else
                {
                    Trace.TraceData(TraceEventType.Warning, "The user was logged out but the session had already expired. Distributed session could therefore not be abandoned");
                }
            }
        }

        private void DoSoapLogout(HttpContext context, string userId)
        {
            try
            {
                var config = _samlConfigService.GetConfig();
                var federationConfig = MapToFederationConfigOptions(config);
                foreach (var action in Actions.Actions.GetActions(federationConfig))
                {
                    Trace.TraceMethodCalled(action.GetType(), "SoapLogoutAction()");
                    action.SoapLogoutAction(this, context, userId);
                    Trace.TraceMethodDone(action.GetType(), "SoapLogoutAction()");
                }
            }
            finally
            {
                Trace.TraceData(TraceEventType.Information, $"Clearing all sessions related to user with id: {userId}");
                SessionStore.AbandonAllSessions(userId);
                Trace.TraceData(TraceEventType.Verbose, "Sessions cleared.");
            }
        }
    }
}
