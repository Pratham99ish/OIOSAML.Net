using Identity.Saml.Schema.Core;

namespace Identity.Saml.Validation
{
    internal interface ISaml20SubjectConfirmationValidator
    {
        void ValidateSubjectConfirmation(SubjectConfirmation subjectConfirmation);
    }
}