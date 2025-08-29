using System;
using System.IO;
using System.Linq;
using System.Xml;
using Identity.Saml.Bindings.SignatureProviders;
using Identity.Saml.config;
using Identity.Saml.Properties;
using Identity.Saml.Schema.Protocol;
using Identity.Saml.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Identity.Saml.Configuration;

namespace Identity.Saml.Bindings
{
    public class HttpArtifactBindingBuilder : HttpSOAPBindingBuilder
    {
        private readonly SAML20FederationConfigOptions _samlConfig;
        private readonly FederationConfigOptions _federationConfig;
        private readonly IMemoryCache _cache;

        public HttpArtifactBindingBuilder(HttpContext context, IServiceProvider serviceProvider) : base(context)
        {
            _samlConfig = serviceProvider.GetRequiredService<SAML20FederationConfigService>().GetConfig();
            _federationConfig = serviceProvider.GetRequiredService<FederationConfigService>().GetConfig();
            _cache = serviceProvider.GetRequiredService<IMemoryCache>();
        }

        /// <summary>
        /// Creates an artifact and redirects the user to the IdP
        /// </summary>
        /// <param name="idpEndPoint">The IdP endpoint</param>
        /// <param name="destination">The destination of the request.</param>
        /// <param name="request">The authentication request.</param>
        public void RedirectFromLogin(IDPEndPointOptions idpEndPoint, IDPEndPointElementOptions destination, Saml20AuthnRequest request)
        {
            var index = _samlConfig.ServiceProvider.ServiceEndpoints.FirstOrDefault(e => e.Type == "signon")?.EndPointIndex ?? 0;
            XmlDocument doc = request.GetXml();

            var shaHashingAlgorithm = SignatureProviderFactory.ValidateShaHashingAlgorithm(idpEndPoint.ShaHashingAlgorithm);
            var signatureProvider = SignatureProviderFactory.CreateFromShaHashingAlgorithmName(shaHashingAlgorithm);
            
            ArtifactRedirect(destination, (short)index, doc);
        }

        /// <summary>
        /// Creates an artifact for the LogoutRequest and redirects the user to the IdP.
        /// </summary>
        /// <param name="idpEndPoint">The IdP endpoint</param>
        /// <param name="destination">The destination of the request.</param>
        /// <param name="request">The logout request.</param>
        public void RedirectFromLogout(IDPEndPointOptions idpEndPoint, IDPEndPointElementOptions destination, Saml20LogoutRequest request)
        {
            var index = _samlConfig.ServiceProvider.ServiceEndpoints.FirstOrDefault(e => e.Type == "logout")?.EndPointIndex ?? 0;
            XmlDocument doc = request.GetXml();

            var shaHashingAlgorithm = SignatureProviderFactory.ValidateShaHashingAlgorithm(idpEndPoint.ShaHashingAlgorithm);
            var signatureProvider = SignatureProviderFactory.CreateFromShaHashingAlgorithmName(shaHashingAlgorithm);
            
            ArtifactRedirect(destination, (short)index, doc);
        }

        /// <summary>
        /// Creates an artifact for the LogoutRequest and redirects the user to the IdP.
        /// </summary>
        /// <param name="idpEndPoint">The IdP endpoint</param>
        /// <param name="destination">The destination of the request.</param>
        /// <param name="request">The logout request.</param>
        /// <param name="relayState">The query string relay state value to add to the communication</param>
        public void RedirectFromLogout(IDPEndPointOptions idpEndPoint, IDPEndPointElementOptions destination, Saml20LogoutRequest request, string relayState)
        {
            var index = _samlConfig.ServiceProvider.ServiceEndpoints.FirstOrDefault(e => e.Type == "logout")?.EndPointIndex ?? 0;
            XmlDocument doc = request.GetXml();

            var shaHashingAlgorithm = SignatureProviderFactory.ValidateShaHashingAlgorithm(idpEndPoint.ShaHashingAlgorithm);
            var signatureProvider = SignatureProviderFactory.CreateFromShaHashingAlgorithmName(shaHashingAlgorithm);
            
            ArtifactRedirect(destination, (short)index, doc, relayState);
        }

        /// <summary>
        /// Creates an artifact for the LogoutResponse and redirects the user to the IdP.
        /// </summary>
        /// <param name="idpEndPoint">The IdP endpoint</param>
        /// <param name="destination">The destination of the response.</param>
        /// <param name="response">The logout response.</param>
        public void RedirectFromLogout(IDPEndPointOptions idpEndPoint, IDPEndPointElementOptions destination, Saml20LogoutResponse response)
        {
            var index = _samlConfig.ServiceProvider.ServiceEndpoints.FirstOrDefault(e => e.Type == "logout")?.EndPointIndex ?? 0;
            XmlDocument doc = response.GetXml();

            var shaHashingAlgorithm = SignatureProviderFactory.ValidateShaHashingAlgorithm(idpEndPoint.ShaHashingAlgorithm);
            var signatureProvider = SignatureProviderFactory.CreateFromShaHashingAlgorithmName(shaHashingAlgorithm);
            
            ArtifactRedirect(destination, (short)index, doc);
        }

        /// <summary>
        /// Handles all artifact creations and redirects.
        /// </summary>
        /// <param name="destination">The destination.</param>
        /// <param name="localEndpointIndex">Index of the local endpoint.</param>
        /// <param name="signedSamlMessage">The signed saml message.</param>
        /// <param name="relayState">The query string relay state value to add to the communication</param>
        private void ArtifactRedirect(IDPEndPointElementOptions destination, short localEndpointIndex, XmlDocument signedSamlMessage, string relayState = null)
        {
            string sourceId = _samlConfig.ServiceProvider.Id;
            byte[] sourceIdHash = ArtifactUtil.GenerateSourceIdHash(sourceId);
            byte[] messageHandle = ArtifactUtil.GenerateMessageHandle();

            string artifact = ArtifactUtil.CreateArtifact(HttpArtifactBindingConstants.ArtifactTypeCode, localEndpointIndex, sourceIdHash, messageHandle);

            _cache.Set(artifact, signedSamlMessage, TimeSpan.FromMinutes(1));

            string destinationUrl = destination.Url + "?" + HttpArtifactBindingConstants.ArtifactQueryStringName + "=" + Uri.EscapeDataString(artifact);
            if (!string.IsNullOrEmpty(relayState))
            {
                destinationUrl += "&relayState=" + relayState;
            }

            // Logging and redirect
            _context.Response.Redirect(destinationUrl);
        }
    }
}