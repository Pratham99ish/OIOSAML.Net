using System;
using Identity.Saml.Schema.Core;

namespace Identity.Saml.Validation
{
    internal interface ISaml20AssertionValidator
    {
        void ValidateAssertion(Assertion assertion);
        void ValidateTimeRestrictions(Assertion assertion, TimeSpan allowedClockSkew, DateTime currentUtcTime);
    }
}