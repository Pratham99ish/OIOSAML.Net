using Identity.Saml.Schema.Core;

namespace Identity.Saml.Validation
{
    internal interface ISaml20SubjectConfirmationDataValidator
    {
        void ValidateSubjectConfirmationData(SubjectConfirmationData data);
    }
}