using System;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using Identity.Saml.Properties;
using Trace=Identity.Saml.Utils.Trace;

namespace Identity.Saml.Specification
{
    /// <summary>
    /// Checks if a certificate is within its validity period
    /// Performs an online revocation check if the certificate contains a CRL url (oid: 2.5.29.31)
    /// </summary>
    public class DefaultCertificateSpecification : ICertificateSpecification
    {
        /// <summary>
        /// Determines whether the specified certificate is considered valid according to the RFC3280 specification.
        /// </summary>
        /// <param name="certificate">The certificate to validate.</param>
        /// <param name="failureReason">If the process fails, the reason is outputted in this variable</param>
        /// <returns>
        ///  <c>true</c> if valid; otherwise, <c>false</c>.
        /// </returns>
        public bool IsSatisfiedBy(X509Certificate2 certificate, out string failureReason)
        {
            failureReason = null;
            try
            {
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 1, 0);
                bool isValid = chain.Build(certificate);
                if (!isValid)
                {
                    failureReason = $"Certificate chain validation failed for certificate '{certificate.Thumbprint}': {chain.ChainStatus[0].StatusInformation}";
                    Trace.TraceData(TraceEventType.Warning, string.Format(Tracing.CertificateIsNotRFC3280Valid, certificate.SubjectName.Name, certificate.Thumbprint, failureReason));
                }
                return isValid;
            }
            catch (Exception e)
            {
                failureReason = $"Validating chain with online revocation check failed for certificate '{certificate.Thumbprint}': {e}";
                Trace.TraceData(TraceEventType.Warning, string.Format(Tracing.CertificateIsNotRFC3280Valid, certificate.SubjectName.Name, certificate.Thumbprint, e));
                return false;
            }
        }
    }
}
