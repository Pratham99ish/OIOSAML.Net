using Identity.Saml.Configuration;
using Microsoft.Extensions.Options;

namespace Identity.Saml.config
{
    public class SAML20FederationConfigService
    {
        private readonly SAML20FederationConfigOptions _options;
        public SAML20FederationConfigService(IOptions<SAML20FederationConfigOptions> options)
        {
            _options = options.Value;
        }

        public SAML20FederationConfigOptions GetConfig() => _options;
    }
}
