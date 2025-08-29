using System;
using System.Xml.Serialization;

namespace dk.nita.saml20.Schema.Metadata
{
    [Serializable]
    [XmlType(Namespace=Saml20Constants.METADATA)]
    public class SPSSODescriptor
    {
        [XmlElement]
        public string[] protocolSupportEnumeration { get; set; }

        [XmlElement]
        public string AuthnRequestsSigned { get; set; }

        [XmlElement]
        public string WantAssertionsSigned { get; set; }

        [XmlElement]
        public IndexedEndpoint[] AssertionConsumerService { get; set; }

        [XmlElement]
        public Endpoint[] SingleLogoutService { get; set; }

        [XmlElement]
        public AttributeConsumingService[] AttributeConsumingService { get; set; }

        [XmlElement]
        public string[] NameIDFormat { get; set; }

        [XmlElement]
        public IndexedEndpoint[] ArtifactResolutionService { get; set; }

        [XmlElement]
        public KeyDescriptor[] KeyDescriptor { get; set; }
    }
}