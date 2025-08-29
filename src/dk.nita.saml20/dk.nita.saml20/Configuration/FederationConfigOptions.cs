namespace dk.nita.saml20.Configuration
{
    public class FederationConfigOptions
    {
        public List<CertificateOptions> SigningCertificates { get; set; } = new();
        public AudienceUrisOptions AudienceUris { get; set; } = new();
        public ActionsOptions Actions { get; set; } = new();
        public AuthnRequestAppenderOptions AuthnRequestAppender { get; set; } = new();
        public int AllowedClockSkewMinutes { get; set; } = 5;
    }

    public class CertificateOptions
    {
        public string Thumbprint { get; set; }
        public string StoreLocation { get; set; }
        public string StoreName { get; set; }
    }

    public class AudienceUrisOptions
    {
        public List<string> Uris { get; set; } = new();
    }

    public class ActionsOptions
    {
        public List<ActionConfigOptions> ActionList { get; set; } = new();
    }

    public class ActionConfigOptions
    {
        public string Name { get; set; }
        public string Type { get; set; }
    }

    public class AuthnRequestAppenderOptions
    {
        public string Type { get; set; }
    }
}
