using System;
using System.Security.Cryptography.X509Certificates;
using Identity.Saml.config;
using Identity.Saml.Properties;
using Microsoft.Extensions.DependencyInjection;
using Identity.Saml.Configuration;

namespace Identity.Saml.Bindings
{
    /// <summary>
    /// Utility functions for use in binding implementations.
    /// </summary>
    public class BindingUtility
    {
        /// <summary>
        /// Validates the SAML20Federation configuration.
        /// </summary>
        /// <param name="errorMessage">The error message. If validation passes, it will be an empty string. Otherwise it will contain a userfriendly message.</param>
        /// <returns>True if validation passes, false otherwise</returns>
        public static bool ValidateConfiguration(IServiceProvider serviceProvider, out string errorMessage)
        {
            var samlConfigService = serviceProvider.GetRequiredService<SAML20FederationConfigService>();
            var federationConfigService = serviceProvider.GetRequiredService<FederationConfigService>();
            var _config = samlConfigService.GetConfig();
            var federationConfig = federationConfigService.GetConfig();

            try
            {
                if (_config == null)
                {
                    errorMessage = Saml20Resources.MissingSaml20Federation;
                    return false;
                }
                if (_config.ServiceProvider == null)
                {
                    errorMessage = Saml20Resources.MissingServiceProvider;
                    return false;
                }
                if (string.IsNullOrEmpty(_config.ServiceProvider.Id))
                {
                    errorMessage = Saml20Resources.MissingServiceProviderId;
                    return false;
                }
                if (federationConfig.SigningCertificates == null || federationConfig.SigningCertificates.Count == 0)
                {
                    errorMessage = Saml20Resources.MissingSigningCertificate;
                    return false;
                }
                try
                {
                    foreach (CertificateOptions certificate in federationConfig.SigningCertificates)
                    {
                        var storeLocation = Enum.Parse<StoreLocation>(certificate.StoreLocation);
                        var storeName = Enum.Parse<StoreName>(certificate.StoreName);
                        using var store = new X509Store(storeName, storeLocation);
                        store.Open(OpenFlags.ReadOnly);
                        var found = store.Certificates.Find(X509FindType.FindByThumbprint, certificate.Thumbprint, false);
                        if (found.Count == 0 || !found[0].HasPrivateKey)
                        {
                            errorMessage = Saml20Resources.SigningCertificateMissingPrivateKey;
                            return false;
                        }
                    }
                }
                catch (Exception ex)
                {
                    errorMessage = Saml20Resources.SigningCertficateLoadError + ex.Message;
                    return false;
                }

                if (_config.IDPEndPoints == null)
                {
                    errorMessage = Saml20Resources.MissingIDPEndpoints;
                    return false;
                }
                // MetadataLocation is now part of POCO config, update check if needed
            }
            catch (Exception ex)
            {
                errorMessage = ex.ToString();
                return false;
            }

            errorMessage = string.Empty;
            return true;
        }
    }
}