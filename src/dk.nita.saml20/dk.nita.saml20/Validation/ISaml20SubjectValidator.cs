using Identity.Saml.Schema.Core;

namespace Identity.Saml.Validation
{
    interface ISaml20SubjectValidator
    {
        void ValidateSubject(Subject subject);
    }
}