using Microsoft.AspNetCore.Http;
using System;
using System.Linq;
using System.Collections.Generic;
using dk.nita.saml20.Bindings;
using dk.nita.saml20.config;
using dk.nita.saml20.Logging;
using dk.nita.saml20.Properties;
using dk.nita.saml20.Schema.Protocol;
using dk.nita.saml20.Utils;
using Microsoft.Extensions.Logging;
using dk.nita.saml20.Configuration;

namespace dk.nita.saml20.protocol
{
    /// <summary>
    /// Base class for all SAML20 specific endpoints.
    /// </summary>
    public abstract class Saml20AbstractEndpointHandler
    {
        /// <summary>
        /// Parameter name for idp choice
        /// </summary>
        public const string IDPChoiceParameterName = "cidp";
        /// <summary>
        /// Parameter name for idp choice
        /// </summary>
        public const string IDPForceAuthn = "forceAuthn";
        /// <summary>
        /// Parameter name for idp choice
        /// </summary>
        public const string IDPIsPassive = "isPassive";
        /// <summary>
        /// Parameter name for NSIS Level of Assurance
        /// </summary>
        public const string NsisLoa = "levelOfAssurance";
        /// <summary>
        /// Parameter name for profile type (Person/Professional)
        /// </summary>
        public const string Profile = "profile";
        /// <summary>
        /// URL parameter name do define a platform used in AppSwitch
        /// </summary>
        public const string AppSwitchPlatform = "appSwitchPlatform";

        /// <summary>
        /// Determines if configuration has been validated
        /// </summary>
        public static bool validated = false;
        protected readonly SAML20FederationConfigService _samlConfigService;
        protected readonly ILogger _logger;

        public Saml20AbstractEndpointHandler(SAML20FederationConfigService samlConfigService, ILogger logger)
        {
            _samlConfigService = samlConfigService;
            _logger = logger;
        }

        // Abstract method to be implemented by derived classes
        protected abstract void Handle(HttpContext context);

        /// <summary>
        /// Enables processing of HTTP Web requests by a custom HttpHandler that implements the <see cref="T:System.Web.IHttpHandler"/> interface.
        /// </summary>
        /// <param name="context">An <see cref="T:System.Web.HttpContext"/> object that provides references to the intrinsic server objects (for example, Request, Response, Session, and Server) used to service HTTP requests.</param>
        public void ProcessRequest(HttpContext context)
        {
            try
            {
                CheckConfiguration(context);
                Handle(context);
            }
            catch (Exception ex)
            {
                var status = new Status {
                    StatusCode = new StatusCode { Value = "urn:oasis:names:tc:SAML:2.0:status:Responder" },
                    StatusMessage = ex.Message
                };
                HandleError(context, status);
            }
        }

        /// <summary>
        /// Checks the configuration elements and redirects to an error page if something is missing or wrong.
        /// </summary>
        /// <param name="ctx"></param>
        private void CheckConfiguration(HttpContext ctx)
        {
            if (validated)
                return;
            var query = ctx.Request.Query;
            var config = _samlConfigService.GetConfig();
            // Example: Find IDP endpoint by id
            if (query.ContainsKey(IDPChoiceParameterName) && !string.IsNullOrEmpty(query[IDPChoiceParameterName]))
            {
                var idpEndpoint = config.IDPEndPoints?.FirstOrDefault(e => e.Id == query[IDPChoiceParameterName]);
                _logger.LogInformation($"Using IDPChoiceParameter: {query[IDPChoiceParameterName]}");
                // ...additional logic...
            }
            // Example: Use default IDP if only one exists
            if (config.IDPEndPoints?.Count == 1)
            {
                var idp = config.IDPEndPoints[0];
                if (idp != null)
                {
                    _logger.LogInformation($"No IdP selected in Common Domain Cookie, using default IdP: {idp.Name}");
                    // ...additional logic...
                }
            }
            // Example: Use IDP marked as default
            var defaultIdp = config.IDPEndPoints?.FirstOrDefault(idp => idp.Default);
            if (defaultIdp != null)
            {
                _logger.LogInformation($"Using IdP marked as default: {defaultIdp.Id}");
                // ...additional logic...
            }
            // Example: Redirect to idpSelectionUrl if set
            if (!string.IsNullOrEmpty(config.CommonDomain?.LocalReaderEndpoint))
            {
                _logger.LogInformation($"Redirecting to idpSelectionUrl for selection of IDP: {config.CommonDomain.LocalReaderEndpoint}");
                ctx.Response.Redirect(config.CommonDomain.LocalReaderEndpoint);
            }
            validated = true;
        }

        /// <summary>
        /// Looks through the Identity Provider configurations and 
        /// </summary>
        public IDPEndPointOptions RetrieveIDPConfiguration(string IDPId)
        {
            if (IDPId == null) return null;
            var config = _samlConfigService.GetConfig();
            return config.IDPEndPoints?.FirstOrDefault(ep => ep.Id == IDPId);
        }

        /// <summary>
        /// Utility function for error handling.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="status">The status.</param>
        protected void HandleError(HttpContext context, Status status)
        {
            string errorMessage = string.Format("ErrorCode: {0}. Message: {1}.", status.StatusCode.Value, status.StatusMessage);
            var errorStatus = new Status { StatusCode = status.StatusCode, StatusMessage = errorMessage };
            HandleErrorInternal(context, errorStatus);
        }

        /// <summary>
        /// Internal error handler to be implemented by derived classes or to return a response
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="status">The status.</param>
        protected virtual void HandleErrorInternal(HttpContext context, Status status)
        {
            context.Response.StatusCode = 400;
            context.Response.ContentType = "application/json";
            context.Response.WriteAsync($"{{\"error\":\"{status.StatusMessage}\"}}");
        }

        /// <summary>
        /// Determine which endpoint to use based on the protocol defaults, configuration data and metadata.
        /// </summary>
        /// <param name="defaultBinding">The binding to use if none has been specified in the configuration and the metadata allows all bindings.</param>
        /// <param name="config">The endpoint as described in the configuration. May be null.</param>
        /// <param name="metadata">A list of endpoints of the given type (eg. SSO or SLO) that the metadata contains. </param>        
        internal static IDPEndPointElement DetermineEndpointConfiguration(string defaultBinding, IDPEndPointElement config, List<IDPEndPointElement> metadata)
        {
            IDPEndPointElement result = new IDPEndPointElement();
            result.Binding = defaultBinding;

            // Determine which binding to use.
            if (config != null)
            {
                result.Binding = config.Binding;
            }
            else
            {
                // Verify that the metadata allows the default binding.
                bool allowed = metadata.Exists(el => el.Binding == defaultBinding);
                if (!allowed)
                {
                    result.Binding = defaultBinding == SAMLBinding.POST ? SAMLBinding.REDIRECT : SAMLBinding.POST;
                }
            }

            if (config != null && !string.IsNullOrEmpty(config.Url))
            {
                result.Url = config.Url;
            }
            else
            {
                IDPEndPointElement endpoint = metadata.Find(el => el.Binding == result.Binding);
                if (endpoint == null)
                    throw new InvalidOperationException($"No IdentityProvider supporting SAML binding {result.Binding} found in metadata");
                result.Url = endpoint.Url;
            }

            return result;
        }

    }
}