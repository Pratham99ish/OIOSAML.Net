using System;
using System.Xml.Serialization;

namespace Identity.Saml.Schema.XEnc
{
    /// <summary>
    /// ItemsChoice for Referencelists
    /// </summary>
    [Serializable]
    [XmlType(Namespace=Saml20Constants.XENC, IncludeInSchema=false)]
    public enum ItemsChoiceType3
    {
        /// <summary>
        /// DataReference
        /// </summary>
        DataReference,


        /// <summary>
        /// KeyReference
        /// </summary>
        KeyReference,
    }
}