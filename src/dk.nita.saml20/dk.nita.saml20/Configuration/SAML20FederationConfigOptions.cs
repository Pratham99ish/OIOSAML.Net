namespace dk.nita.saml20.Configuration
{
    public class SAML20FederationConfigOptions
    {
        public RequestedAttributesOptions RequestedAttributes { get; set; } = new();
        public ServiceProviderOptions ServiceProvider { get; set; } = new();
        public CommonDomainOptions CommonDomain { get; set; } = new();
        public string NameIdFormat { get; set; } = "persistent";
        public bool ShowError { get; set; } = false;
        public bool AllowAssuranceLevel { get; set; } = false;
        public string MinimumAssuranceLevel { get; set; } = "3";
        public string MinimumNsisLoa { get; set; } = "Substantial";
        public List<IDPEndPointOptions> IDPEndPoints { get; set; } = new();
        public ConfigMetadataOptions Metadata { get; set; } = new();
        public List<AppSwitchReturnUrlOptions> AppSwitchReturnURL { get; set; } = new();
    }

    public class RequestedAttributesOptions
    {
        public List<AttributeOptions> Attributes { get; set; } = new();
    }

    public class AttributeOptions
    {
        public string Name { get; set; }
        public bool IsRequired { get; set; }
    }

    public class ServiceProviderOptions
    {
        public string Id { get; set; }
        public string Server { get; set; }
        public List<ServiceEndpointOptions> ServiceEndpoints { get; set; } = new();
        public OrganizationOptions Organization { get; set; } = new();
        public List<ContactOptions> ContactPerson { get; set; } = new();
    }

    public class ServiceEndpointOptions
    {
        public string LocalPath { get; set; }
        public string Type { get; set; }
        public ushort EndPointIndex { get; set; }
        public string RedirectUrl { get; set; }
        public string Binding { get; set; }
        public string ErrorBehaviour { get; set; }
    }

    public class OrganizationOptions
    {
        public string Name { get; set; }
        public string DisplayName { get; set; }
        public string Url { get; set; }
    }

    public class ContactOptions
    {
        public string Type { get; set; }
        public string Company { get; set; }
        public string GivenName { get; set; }
        public string SurName { get; set; }
        public string EmailAddress { get; set; }
        public string TelephoneNumber { get; set; }
    }

    public class CommonDomainOptions
    {
        public bool Enabled { get; set; }
        public string LocalReaderEndpoint { get; set; }
    }

    public class IDPEndPointOptions
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string ResponseEncoding { get; set; }
        public bool QuirksMode { get; set; }
        public bool OmitAssertionSignatureCheck { get; set; }
        public bool ForceAuthn { get; set; }
        public bool IsPassive { get; set; }
        public bool Default { get; set; }
        public string ShaHashingAlgorithm { get; set; }
        public CertificateValidationOptions CertificateValidation { get; set; } = new();
        public HttpBasicAuthOptions AttributeQuery { get; set; } = new();
        public HttpBasicAuthOptions ArtifactResolution { get; set; } = new();
        public IDPEndPointElementOptions SSOEndpoint { get; set; } = new();
        public IDPEndPointElementOptions SLOEndpoint { get; set; } = new();
        public CDCOptions CDC { get; set; } = new();
    }

    public class CertificateValidationOptions
    {
        public List<CertificateValidationElementOptions> CertificateValidations { get; set; } = new();
    }

    public class CertificateValidationElementOptions
    {
        public string Type { get; set; }
        // Add other properties if needed
    }

    public class HttpBasicAuthOptions
    {
        public bool Enabled { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class IDPEndPointElementOptions
    {
        public string Url { get; set; }
        public string Binding { get; set; }
        public string ForceProtocolBinding { get; set; }
        public string IdpTokenAccessor { get; set; }
    }

    public class CDCOptions
    {
        public ExtraSettingsOptions ExtraSettings { get; set; } = new();
    }

    public class ExtraSettingsOptions
    {
        public List<KeyValueOptions> KeyValues { get; set; } = new();
    }

    public class KeyValueOptions
    {
        public string Key { get; set; }
        public string Value { get; set; }
    }

    public class ConfigMetadataOptions
    {
        public bool IncludeArtifactEndpoints { get; set; }
    }

    public class AppSwitchReturnUrlOptions
    {
        public string Platform { get; set; }
        public string Value { get; set; }
    }
}
