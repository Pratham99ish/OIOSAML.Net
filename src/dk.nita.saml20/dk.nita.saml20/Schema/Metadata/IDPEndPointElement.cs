using System;
using System.Xml.Serialization;

namespace Identity.Saml.Schema.Metadata
{
    /// <summary>
    /// Minimal legacy endpoint mapping class for SAML bindings.
    /// </summary>
    [Serializable]
    [XmlType(Namespace=Saml20Constants.METADATA)]
    public class IDPEndPointElement
    {
        /// <summary>
        /// URL of the endpoint.
        /// </summary>
        [XmlAttribute]
        public string Url { get; set; }

        /// <summary>
        /// Binding type of the endpoint.
        /// </summary>
        [XmlAttribute]
        public string Binding { get; set; }

        /// <summary>
        /// Force a specific protocol binding.
        /// </summary>
        [XmlAttribute]
        public string ForceProtocolBinding { get; set; }

        /// <summary>
        /// IDP Token Accessor.
        /// </summary>
        [XmlAttribute]
        public string IdpTokenAccessor { get; set; }

        public IDPEndPointElement() { }

        public IDPEndPointElement(Endpoint endpoint)
        {
            Url = endpoint.Location;
            Binding = endpoint.Binding;
            ForceProtocolBinding = null;
            IdpTokenAccessor = null;
        }

        public IDPEndPointElement(IndexedEndpoint endpoint)
        {
            Url = endpoint.Location;
            Binding = endpoint.Binding;
            ForceProtocolBinding = null;
            IdpTokenAccessor = null;
        }
    }
}
