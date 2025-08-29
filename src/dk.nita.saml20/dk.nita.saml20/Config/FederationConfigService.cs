using dk.nita.saml20.Configuration;
using Microsoft.Extensions.Options;

namespace dk.nita.saml20.config
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
