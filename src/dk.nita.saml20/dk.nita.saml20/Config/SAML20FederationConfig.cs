using System.Collections.Generic;
using System.Linq;
using dk.nita.saml20.Configuration;

namespace dk.nita.saml20.config
{
    // This class is now a wrapper for the POCO config options loaded from appsettings.json
    public class SAML20FederationConfig
    {
        public SAML20FederationConfigOptions Options { get; }

        public SAML20FederationConfig(SAML20FederationConfigOptions options)
        {
            Options = options;
        }

        public dk.nita.saml20.Configuration.ServiceProviderOptions ServiceProvider => Options.ServiceProvider;
        public List<IDPEndPointOptions> IDPEndPoints => Options.IDPEndPoints;
        public RequestedAttributesOptions RequestedAttributes => Options.RequestedAttributes;
        public CommonDomainOptions CommonDomain => Options.CommonDomain;
        public string NameIdFormat => Options.NameIdFormat;
        public bool ShowError => Options.ShowError;
        public bool AllowAssuranceLevel => Options.AllowAssuranceLevel;
        public string MinimumAssuranceLevel => Options.MinimumAssuranceLevel;
        public string MinimumNsisLoa => Options.MinimumNsisLoa;
        public ConfigMetadataOptions Metadata => Options.Metadata;
        public List<AppSwitchReturnUrlOptions> AppSwitchReturnURL => Options.AppSwitchReturnURL;

        public IDPEndPointOptions FindEndPoint(string endPointId)
        {
            return IDPEndPoints?.FirstOrDefault(ep => ep.Id == endPointId);
        }

        public string FindAppSwitchReturnUrlForPlatform(string appSwitchPlatform)
        {
            return AppSwitchReturnURL?.FirstOrDefault(x => x.Platform == appSwitchPlatform)?.Value;
        }
    }
}