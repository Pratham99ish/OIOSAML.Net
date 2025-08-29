using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using dk.nita.saml20.config;
using dk.nita.saml20.Configuration;

namespace dk.nita.saml20.Controllers
{
    /// <summary>
    /// Base class for ASP.NET Core Web API controllers in the SAML20 project.
    /// Provides common config and logging access.
    /// </summary>
    [ApiController]
    public abstract class BaseApiController : ControllerBase
    {
        protected readonly SAML20FederationConfigService _samlConfigService;
        protected readonly ILogger _logger;

        public BaseApiController(SAML20FederationConfigService samlConfigService, ILogger logger)
        {
            _samlConfigService = samlConfigService;
            _logger = logger;
        }

        /// <summary>
        /// Gets the current SAML20FederationConfig POCO.
        /// </summary>
        protected SAML20FederationConfigOptions SAMLConfig => _samlConfigService.GetConfig();

        // Add shared error handling, response helpers, etc. here as needed
    }
}
