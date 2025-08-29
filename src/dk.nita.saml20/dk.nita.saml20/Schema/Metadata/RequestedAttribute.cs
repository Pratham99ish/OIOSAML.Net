using System;
using System.Xml.Serialization;

namespace Identity.Saml.Schema.Metadata
{
    /// <summary>
    /// The &lt;RequestedAttribute&gt; element specifies a service provider's interest in a specific SAML
    /// attribute, optionally including specific values.
    /// </summary>
    [Serializable]
    [XmlType(Namespace = Saml20Constants.METADATA)]
    public class RequestedAttribute
    {
        /// <summary>
        /// Gets or sets the name of the requested attribute.
        /// </summary>
        /// <value>
        /// The name of the requested attribute.
        /// </value>
        [XmlAttribute]
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this instance is required.
        /// Optional XML attribute indicates if the service requires the corresponding SAML attribute in order
        /// to function at all (as opposed to merely finding an attribute useful or desirable).
        /// </summary>
        /// <value>
        /// 	<c>true</c> if this instance is required; otherwise, <c>false</c>.
        /// </value>
        [XmlAttribute]
        public bool isRequired { get; set; }

        /// <summary>
        /// Gets or sets the format of the name of the requested attribute.
        /// </summary>
        /// <value>
        /// The format of the name of the requested attribute.
        /// </value>
        [XmlAttribute]
        public string NameFormat { get; set; }
    }
}