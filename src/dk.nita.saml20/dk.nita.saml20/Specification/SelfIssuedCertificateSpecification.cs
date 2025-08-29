using System;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using Identity.Saml.Properties;
using Trace=Identity.Saml.Utils.Trace;

namespace Identity.Saml.Specification
{
    /// <summary>
    /// Validates a selfsigned certificate
    /// </summary>
    public class SelfIssuedCertificateSpecification : ICertificateSpecification
    {
        /// <summary>
        /// Determines whether the specified certificate is considered valid by this specification.
        /// Always returns true. No online validation attempted.
        /// </summary>
        /// <param name="certificate">The certificate to validate.</param>
        /// <param name="failureReason">If the process fails, the reason is outputted in this variable</param>
        /// <returns>
        /// 	<c>true</c>.
        /// </returns>
        public bool IsSatisfiedBy(X509Certificate2 certificate, out string failureReason)
        {
            failureReason = null;
            try
            {
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 1, 0);
                bool isValid = chain.Build(certificate);
                if (!isValid)
                {
                    failureReason = $"Self-signed certificate validation failed for certificate '{certificate.Thumbprint}': {chain.ChainStatus[0].StatusInformation}";
                    Trace.TraceData(TraceEventType.Warning, string.Format(Tracing.CertificateIsNotRFC3280Valid, certificate.SubjectName.Name, certificate.Thumbprint, failureReason));
                }
                return isValid;
            }
            catch (Exception e)
            {
                failureReason = $"Validating self-signed certificate failed for certificate '{certificate.Thumbprint}': {e}";
                Trace.TraceData(TraceEventType.Warning, string.Format(Tracing.CertificateIsNotRFC3280Valid, certificate.SubjectName.Name, certificate.Thumbprint, e));
                return false;
            }
        }
    }
}
