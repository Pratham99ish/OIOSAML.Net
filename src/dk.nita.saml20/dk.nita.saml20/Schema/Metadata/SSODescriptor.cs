using System;
using System.Xml.Serialization;

namespace Identity.Saml.Schema.Metadata
{
    [Serializable]
    [XmlType(Namespace=Saml20Constants.METADATA)]
    public class SSODescriptor
    {
        [XmlElement]
        public Endpoint[] SingleLogoutService { get; set; }

        [XmlElement]
        public IndexedEndpoint[] ArtifactResolutionService { get; set; }
    }
}