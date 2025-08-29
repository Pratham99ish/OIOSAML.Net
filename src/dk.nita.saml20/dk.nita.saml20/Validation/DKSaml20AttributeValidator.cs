using System;
using Identity.Saml.Profiles.DKSaml20;
using Identity.Saml.Schema.Core;
using Identity.Saml.Schema.Protocol;

namespace Identity.Saml.Validation
{
    internal class DKSaml20AttributeValidator : ISaml20AttributeValidator
    {
        public void ValidateAttribute(SamlAttribute samlAttribute)
        {            
            if (!Uri.IsWellFormedUriString(samlAttribute.Name, UriKind.Absolute))
                throw new DKSaml20FormatException("The SAML profile requires that an attribute's \"Name\" is an URI.");

            if (samlAttribute.AttributeValue == null)
                return;

            foreach (object val in samlAttribute.AttributeValue)
            {
                if (val is string)
                    continue;

                throw new DKSaml20FormatException("The SAML profile requires that all attribute values are of type \"xs:string\".");
            }
        }

        public void ValidateEncryptedAttribute(EncryptedElement encryptedElement)
        {
            throw new DKSaml20FormatException("The SAML profile does not support the EncryptedAttribute element");
        }
    }
}