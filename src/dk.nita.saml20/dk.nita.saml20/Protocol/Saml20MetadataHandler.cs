using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Linq;
using Microsoft.AspNetCore.Http;
using Identity.Saml.config;
using Saml2.Properties;
using System.Security.Cryptography.Xml;
using System.Collections.Generic;
using Identity.Saml.Configuration;
using Identity.Saml.Schema.XmlDSig;

namespace Identity.Saml.Protocol
{
    /// <summary>
    /// The handler that exposes a metadata endpoint to the other parties of the federation.
    /// </summary>
    public class Saml20MetadataHandler
    {
        /// <summary>
        /// Processes the HTTP request for the metadata endpoint.
        /// </summary>
        /// <param name="context">The HTTP context.</param>
        /// <param name="config">The SAML federation config options.</param>
        /// <param name="signingCertificates">The signing certificates.</param>
        public void ProcessRequest(HttpContext context, SAML20FederationConfigOptions config, List<X509Certificate2> signingCertificates)
        {
            var encoding = context.Request.Query["encoding"].FirstOrDefault();
            try
            {
                if (!string.IsNullOrEmpty(encoding))
                    context.Response.ContentType = "application/xml; charset=" + encoding;
            }
            catch (ArgumentException)
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                context.Response.WriteAsync($"{{\"error\":\"Unknown encoding: {encoding}\"}}");
                return;
            }

            var sign = true;
            try
            {
                string param = context.Request.Query["sign"].FirstOrDefault();
                if (!string.IsNullOrEmpty(param))
                    sign = Convert.ToBoolean(param);
            }
            catch (FormatException)
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                context.Response.WriteAsync($"{{\"error\":\"Invalid sign parameter\"}}");
                return;
            }

            context.Response.ContentType = "application/samlmetadata+xml";
            context.Response.Headers["Content-Disposition"] = "attachment; filename=metadata.xml";

            CreateMetadataDocument(context, config, signingCertificates, sign, encoding);
        }

        private void CreateMetadataDocument(HttpContext context, SAML20FederationConfigOptions config, List<X509Certificate2> signingCertificates, bool sign, string encoding)
        {
            var keyinfos = new List<Identity.Saml.Schema.XmlDSig.KeyInfo>();
            foreach (var certificate in signingCertificates)
            {
                var x509Data = new X509Data
                {
                    Items = new object[] { certificate.RawData },
                    ItemsElementName = new[] { ItemsChoiceType.X509Certificate }
                };
                var keyinfo = new Identity.Saml.Schema.XmlDSig.KeyInfo
                {
                    Items = new object[] { x509Data }
                };
                keyinfos.Add(keyinfo);
            }
            var federationConfig = new SAML20FederationConfig(config);
            var doc = new Saml20MetadataDocument(federationConfig, keyinfos, sign);
            var enc = string.IsNullOrEmpty(encoding) ? Encoding.UTF8 : Encoding.GetEncoding(encoding);
            context.Response.WriteAsync(doc.ToXml(enc));
        }
    }
}