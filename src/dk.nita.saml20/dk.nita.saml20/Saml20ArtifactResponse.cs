using System;
using System.Xml;
using Identity.Saml.config;
using Identity.Saml.Schema.Core;
using Identity.Saml.Schema.Protocol;
using Identity.Saml.Utils;
using Saml2.Properties;
using Identity.Saml.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Identity.Saml
{
    /// <summary>
    /// Encapsulates the ArtificatResponse schema class
    /// </summary>
    public class Saml20ArtifactResponse
    {
        private ArtifactResponse _artifactResponse;

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20ArtifactResponse"/> class.
        /// </summary>
        public Saml20ArtifactResponse()
        {
            _artifactResponse = new ArtifactResponse();
            _artifactResponse.Version = Saml20Constants.Version;
            _artifactResponse.ID = "id" + Guid.NewGuid().ToString("N");
            _artifactResponse.Issuer = new NameID();
            _artifactResponse.IssueInstant = DateTime.Now;
            _artifactResponse.Status = new Status();
            _artifactResponse.Status.StatusCode = new StatusCode();
        }

        /// <summary>
        /// Gets or sets the issuer.
        /// </summary>
        /// <value>The issuer.</value>
        public string Issuer
        {
            get { return _artifactResponse.Issuer.Value; }
            set { _artifactResponse.Issuer.Value = value; }
        }

        /// <summary>
        /// Gets or sets InResponseTo.
        /// </summary>
        /// <value>The in response to.</value>
        public string InResponseTo
        {
            get { return _artifactResponse.InResponseTo; }
            set { _artifactResponse.InResponseTo = value; }
        }

        /// <summary>
        /// Gets or sets the SAML element.
        /// </summary>
        /// <value>The SAML element.</value>
        public XmlElement SamlElement
        {
            get { return _artifactResponse.Any;  }
            set { _artifactResponse.Any = value;  }
        }

        /// <summary>
        /// Gets the ID.
        /// </summary>
        /// <value>The ID.</value>
        public string ID
        {
            get { return _artifactResponse.ID; }
        }

        /// <summary>
        /// Gets or sets the status code.
        /// </summary>
        /// <value>The status code.</value>
        public string StatusCode
        {
            get { return _artifactResponse.Status.StatusCode.Value; }
            set { _artifactResponse.Status.StatusCode.Value = value; }
        }

        /// <summary>
        /// Returns the ArtifactResponse as an XML document.
        /// </summary>
        public XmlDocument GetXml()
        {
            XmlDocument doc = new XmlDocument();
            doc.XmlResolver = null;
            doc.PreserveWhitespace = true;
            doc.LoadXml(Serialization.SerializeToXmlString(_artifactResponse));
            return doc;
        }

        /// <summary>
        /// Gets a default instance of this class with proper values set.
        /// </summary>
        /// <returns></returns>
        public static Saml20ArtifactResponse GetDefault(IServiceProvider serviceProvider)
        {
            var configService = serviceProvider.GetRequiredService<SAML20FederationConfigService>();
            var config = configService.GetConfig();
            if (config.ServiceProvider == null || string.IsNullOrEmpty(config.ServiceProvider.Id))
                throw new Saml20FormatException(Resources.ServiceProviderNotSet);
            Saml20ArtifactResponse result = new Saml20ArtifactResponse();
            result.Issuer = config.ServiceProvider.Id;
            return result;
        }
    }
}