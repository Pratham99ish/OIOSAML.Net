using System;
using System.Xml.Serialization;

namespace Identity.Saml.Schema.Metadata
{
    /// <summary>
    /// The &lt;AttributeConsumingService&gt; element defines a particular service offered by the service
    /// provider in terms of the attributes the service requires or desires.
    /// </summary>
    [Serializable]
    [XmlType(Namespace=Saml20Constants.METADATA)]
    public class AttributeConsumingService
    {
        /// <summary>
        /// Gets or sets the index.
        /// A required attribute that assigns a unique integer value to the element so that it can be referenced
        /// in a protocol message.
        /// </summary>
        /// <value>The index.</value>
        [XmlAttribute]
        public ushort index { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this instance is default.
        /// Identifies the default service supported by the service provider. Useful if the specific service is not
        /// otherwise indicated by application context. If omitted, the value is assumed to be false.
        /// </summary>
        /// <value>
        /// 	<c>true</c> if this instance is default; otherwise, <c>false</c>.
        /// </value>
        [XmlAttribute]
        public bool isDefault { get; set; }

        /// <summary>
        /// Gets or sets the name of the service.
        /// One or more language-qualified names for the service.
        /// </summary>
        /// <value>The name of the service.</value>
        [XmlElement]
        public LocalizedName[] ServiceName { get; set; }

        /// <summary>
        /// Gets or sets the requested attribute.
        /// One or more elements specifying attributes required or desired by this service.
        /// </summary>
        /// <value>The requested attribute.</value>
        [XmlElement]
        public RequestedAttribute[] RequestedAttribute { get; set; }
    }
}