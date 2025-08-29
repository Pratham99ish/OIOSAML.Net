using System;
using System.Xml.Serialization;

namespace Identity.Saml.Schema.Metadata
{
    /// <summary>
    /// The &lt;ContactPerson&gt; element specifies basic contact information about a person responsible in some
    /// capacity for a SAML entity or role. The use of this element is always optional. Its content is informative in
    /// nature and does not directly map to any core SAML elements or attributes.
    /// </summary>
    [Serializable]
    [XmlType(Namespace=Saml20Constants.METADATA)]
    public class Contact
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Contact"/> class.
        /// </summary>
        public Contact() {}

        /// <summary>
        /// Initializes a new instance of the <see cref="Contact"/> class.
        /// </summary>
        /// <param name="contactType">Type of the contact.</param>
        public Contact(ContactType contactType)
        {
            contactTypeField = contactType;
        }

        /// <summary>
        /// The XML Element name of this class
        /// </summary>
        public const string ELEMENT_NAME = "ContactPerson";

        private ContactType contactTypeField;


        /// <summary>
        /// Gets or sets the type of the contact.
        /// Specifies the type of contact using the ContactTypeType enumeration. The possible values are
        /// technical, support, administrative, billing, and other.
        /// </summary>
        /// <value>The type of the contact.</value>
        [XmlAttribute]
        public ContactType Type
        {
            get { return contactTypeField; }
            set { contactTypeField = value; }
        }


        /// <summary>
        /// Gets or sets the company.
        /// Optional string element that specifies the name of the company for the contact person.
        /// </summary>
        /// <value>The company.</value>
        [XmlElement]
        public string Company { get; set; }


        /// <summary>
        /// Gets or sets the name of the given.
        /// Optional string element that specifies the given (first) name of the contact person.
        /// </summary>
        /// <value>The name of the given.</value>
        [XmlElement]
        public string GivenName { get; set; }


        /// <summary>
        /// Optional string element that specifies the surname of the contact person.
        /// </summary>
        /// <value>The name of the sur.</value>
        [XmlElement]
        public string SurName { get; set; }


        /// <summary>
        /// Gets or sets the email address.
        /// Zero or more elements containing mailto: URIs representing e-mail addresses belonging to the
        /// contact person.
        /// </summary>
        /// <value>The email address.</value>
        [XmlElement]
        public string EmailAddress { get; set; }


        /// <summary>
        /// Gets or sets the telephone number.
        /// Zero or more string elements specifying a telephone number of the contact person.
        /// </summary>
        /// <value>The telephone number.</value>
        [XmlElement]
        public string TelephoneNumber { get; set; }
    }
}