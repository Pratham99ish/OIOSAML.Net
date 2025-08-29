using Identity.Saml.Schema.Core;
using Identity.Saml.Schema.Protocol;

namespace Identity.Saml.Validation
{
    internal interface ISaml20NameIDValidator
    {
        void ValidateNameID(NameID nameID);
        void ValidateEncryptedID(EncryptedElement encryptedID);
    }
}