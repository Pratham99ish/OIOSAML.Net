using System;
using System.Xml.Serialization;

namespace dk.nita.saml20.Schema.Metadata
{
    /// <summary>
    /// The &lt;Organization&gt; element specifies basic information about an organization responsible for a SAML
    /// entity or role. The use of this element is always optional. Its content is informative in nature and does not
    /// directly map to any core SAML elements or attributes.
    /// </summary>
    [Serializable]
    [XmlType(Namespace=Saml20Constants.METADATA)]
    public class Organization {
        
        /// <summary>
        /// Gets or sets the name of the organization.
        /// One or more language-qualified names that may or may not be suitable for human consumption
        /// </summary>
        /// <value>The name of the organization.</value>
        [XmlElementAttribute("OrganizationName")]
        public LocalizedName[] OrganizationName { get; set; }


        /// <summary>
        /// Gets or sets the display name of the organization.
        /// One or more language-qualified names that are suitable for human consumption.
        /// </summary>
        /// <value>The display name of the organization.</value>
        [XmlElementAttribute("OrganizationDisplayName")]
        public LocalizedName[] OrganizationDisplayName { get; set; }


        /// <summary>
        /// Gets or sets the organization URL.
        /// One or more language-qualified URIs that specify a location to which to direct a user for additional
        /// information. Note that the language qualifier refers to the content of the material at the specified
        /// location.
        /// </summary>
        /// <value>The organization URL.</value>
        [XmlElementAttribute("OrganizationURL")]
        public LocalizedURI[] OrganizationURL { get; set; }
    }
}