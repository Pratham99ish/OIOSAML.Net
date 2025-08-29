using Identity.Saml.Configuration;
using Microsoft.Extensions.Options;

namespace Identity.Saml.config
{
    public class FederationConfigService
    {
        private readonly FederationConfigOptions _options;
        public FederationConfigService(IOptions<FederationConfigOptions> options)
        {
            _options = options.Value;
        }

        public FederationConfigOptions GetConfig() => _options;
    }
}
