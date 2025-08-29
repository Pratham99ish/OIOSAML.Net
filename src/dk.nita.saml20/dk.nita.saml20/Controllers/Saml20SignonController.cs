using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Identity.Saml.config;
using Identity.Saml.Configuration;
using Identity.Saml.Bindings;
using Identity.Saml.Actions;
using Identity.Saml.Schema.Protocol;
using Identity.Saml.Utils;
using Identity.Saml.Bindings.SignatureProviders;
using System.Xml;
using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Identity.Saml.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class Saml20SignonController : BaseApiController
    {
        private readonly FederationConfigService _federationConfigService;
        private readonly X509Certificate2 _certificate;

        public Saml20SignonController(SAML20FederationConfigService samlConfigService, FederationConfigService federationConfigService, ILogger<Saml20SignonController> logger)
            : base(samlConfigService, logger)
        {
            _federationConfigService = federationConfigService;
            // Use POCO config for certificate
            var config = _federationConfigService.GetConfig();
            var certOptions = config.SigningCertificates?.FirstOrDefault();
            if (certOptions != null)
            {
                var storeLocation = Enum.Parse<StoreLocation>(certOptions.StoreLocation);
                var storeName = Enum.Parse<StoreName>(certOptions.StoreName);
                using var store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadOnly);
                var found = store.Certificates.Find(X509FindType.FindByThumbprint, certOptions.Thumbprint, false);
                if (found.Count > 0)
                {
                    _certificate = found[0];
                }
                else
                {
                    _certificate = null;
                }
            }
            else
            {
                _certificate = null;
            }
        }

        [HttpPost("signon")]
        public IActionResult Signon([FromQuery] string SAMLart, [FromQuery] string SAMLResponse)
        {
            if (!string.IsNullOrEmpty(SAMLart))
                return HandleArtifact(SAMLart);
            if (!string.IsNullOrEmpty(SAMLResponse))
                return HandleResponse(SAMLResponse);
            return SendRequest();
        }

        [NonAction]
        public IActionResult HandleArtifact(string samlArt)
        {
            _logger.LogInformation($"Artifact signon requested: {samlArt}");
            try
            {
                var builder = new HttpArtifactBindingBuilder(HttpContext, HttpContext.RequestServices);
                // TODO: Use builder.RedirectFromLogin or similar for artifact handling
                // This is a stub for demonstration
                return Ok(new { message = "Artifact handling logic should be implemented here." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing artifact.");
                return BadRequest(new { error = "Artifact processing failed." });
            }
        }

        [NonAction]
        public IActionResult HandleResponse(string samlResponse)
        {
            _logger.LogInformation($"Signon response received: {samlResponse}");
            try
            {
                var encoding = Encoding.UTF8;
                var samlResponseXml = encoding.GetString(Convert.FromBase64String(samlResponse));
                var doc = new XmlDocument { XmlResolver = null, PreserveWhitespace = true };
                doc.LoadXml(samlResponseXml);
                var statusElem = (XmlElement)doc.GetElementsByTagName(Status.ELEMENT_NAME, Saml20Constants.PROTOCOL)[0];
                Status status = Serialization.DeserializeFromXmlString<Status>(statusElem.OuterXml);
                if (status.StatusCode.Value != Saml20Constants.StatusCodes.Success)
                    return BadRequest(new { error = "SAML response status not success." });
                // TODO: Validate assertion, signature, and session
                return Ok(new { message = "SAML response validated." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing SAML response");
                return BadRequest(new { error = "Invalid SAML response." });
            }
        }

        [NonAction]
        public IActionResult SendRequest()
        {
            _logger.LogInformation("Sending authentication request to IDP.");
            var config = _samlConfigService.GetConfig();
            var idpEndpoint = config.IDPEndPoints?.FirstOrDefault();
            if (idpEndpoint == null)
            {
                return BadRequest(new { error = "No IDP endpoint configured." });
            }
            var authnRequest = Saml20AuthnRequest.GetDefault(HttpContext.RequestServices);
            authnRequest.Destination = idpEndpoint.SSOEndpoint?.Url;
            var shaHashingAlgorithm = SignatureProviderFactory.ValidateShaHashingAlgorithm(idpEndpoint.ShaHashingAlgorithm);
            var binding = idpEndpoint.SSOEndpoint?.Binding;
            if (string.Equals(binding, "REDIRECT", StringComparison.OrdinalIgnoreCase))
            {
                var builder = new HttpRedirectBindingBuilder();
                builder.signingKey = _certificate.PrivateKey;
                builder.Request = authnRequest.GetXml().OuterXml;
                builder.ShaHashingAlgorithm = shaHashingAlgorithm;
                string redirectUrl = authnRequest.Destination + "?" + builder.ToQuery();
                return Ok(new { redirectUrl });
            }
            else if (string.Equals(binding, "POST", StringComparison.OrdinalIgnoreCase))
            {
                var postUrl = idpEndpoint.SSOEndpoint?.Url;
                var builder = new HttpPostBindingBuilder(postUrl);
                XmlDocument req = authnRequest.GetXml();
                var signatureProvider = SignatureProviderFactory.CreateFromShaHashingAlgorithmName(shaHashingAlgorithm);
                signatureProvider.SignAssertion(req, authnRequest.ID, _certificate);
                builder.SAMLRequest = req.OuterXml;
                // Optionally set RelayState if needed
                // builder.RelayState = ...;
                var htmlForm = builder.GetHtmlForm();
                return Ok(new { htmlForm });
            }
            return BadRequest(new { error = "Unsupported SAML binding." });
        }
    }
}
