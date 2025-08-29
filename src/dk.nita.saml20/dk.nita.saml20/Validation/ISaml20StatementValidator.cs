using Identity.Saml.Schema.Core;

namespace Identity.Saml.Validation
{
    internal interface ISaml20StatementValidator
    {
        void ValidateStatement(StatementAbstract statement);
    }
}