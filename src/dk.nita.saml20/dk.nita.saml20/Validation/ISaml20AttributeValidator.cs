using Identity.Saml.Schema.Core;
using Identity.Saml.Schema.Protocol;

namespace Identity.Saml.Validation
{
    internal interface ISaml20AttributeValidator
    {
        void ValidateAttribute(SamlAttribute samlAttribute);
        void ValidateEncryptedAttribute(EncryptedElement encryptedElement);
    }
}