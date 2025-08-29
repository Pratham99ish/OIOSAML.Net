using Microsoft.AspNetCore.Mvc;
using Identity.Saml.config;

namespace Identity.Saml.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ControlController : ControllerBase
    {
        private readonly SAML20FederationConfigService _samlConfigService;
        private readonly FederationConfigService _federationConfigService;

        public ControlController(SAML20FederationConfigService samlConfigService, FederationConfigService federationConfigService)
        {
            _samlConfigService = samlConfigService;
            _federationConfigService = federationConfigService;
        }

        [HttpGet("status")]
        public IActionResult GetStatus()
        {
            var samlConfig = _samlConfigService.GetConfig();
            var federationConfig = _federationConfigService.GetConfig();
            return Ok(new
            {
                SAML20FederationConfig = samlConfig,
                FederationConfig = federationConfig
            });
        }
    }
}
