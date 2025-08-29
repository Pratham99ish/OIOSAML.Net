using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Web;
using System.Xml;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Identity.Saml.Bindings;
using Identity.Saml.Bindings.SignatureProviders;
using Identity.Saml.PrincipalCache;
using Identity.Saml.config;
using Identity.Saml.identity;
using Identity.Saml.Properties;
using Identity.Saml.protocol;
using Identity.Saml.Schema.Core;
using Identity.Saml.Schema.Protocol;
using Identity.Saml.Utils;
using Saml2.Properties;
using Trace = Identity.Saml.Utils.Trace;
using Identity.Saml.Configuration;

namespace Identity.Saml
{
    /// <summary>
    /// Performs SAML2.0 attribute queries
    /// </summary>
    public class Saml20AttributeQuery
    {
        private readonly AttributeQuery _attrQuery;
        private readonly List<SamlAttribute> _attributes;

        private Saml20AttributeQuery()
        {
            _attrQuery = new AttributeQuery();
            _attrQuery.Version = Saml20Constants.Version;
            _attrQuery.ID = "id" + Guid.NewGuid().ToString("N");
            _attrQuery.Issuer = new NameID();
            _attrQuery.IssueInstant = DateTime.Now;
            _attrQuery.Subject = new Subject();
            _attributes = new List<SamlAttribute>();
        }

        public string Issuer
        {
            get { return _attrQuery.Issuer.Value; }
            set { _attrQuery.Issuer.Value = value; }
        }
        public string Consent
        {
            get { return _attrQuery.Consent; }
            set { _attrQuery.Consent = value; }
        }
        public string ID => _attrQuery.ID;

        public void AddAttribute(string attrName)
        {
            AddAttribute(attrName, Saml20NameFormat.BASIC);
        }
        public void AddAttribute(string attrName, Saml20NameFormat nameFormat)
        {
            List<SamlAttribute> found = _attributes.FindAll(at => at.Name == attrName && at.NameFormat == GetNameFormat(nameFormat));
            if (found.Count > 0)
                throw new InvalidOperationException($"An attribute with name \"{attrName}\" and name format \"{Enum.GetName(typeof(Saml20NameFormat), nameFormat)}\" has already been added");
            SamlAttribute attr = new SamlAttribute();
            attr.Name = attrName;
            attr.NameFormat = GetNameFormat(nameFormat);
            _attributes.Add(attr);
        }
        private static string GetNameFormat(Saml20NameFormat nameFormat)
        {
            return nameFormat switch
            {
                Saml20NameFormat.BASIC => SamlAttribute.NAMEFORMAT_BASIC,
                Saml20NameFormat.URI => SamlAttribute.NAMEFORMAT_URI,
                _ => throw new ArgumentException($"Unsupported nameFormat: {Enum.GetName(typeof(Saml20NameFormat), nameFormat)}", "nameFormat")
            };
        }

        // New PerformQuery signature: pass config and endpoint
        public async Task PerformQueryAsync(HttpContext context, SAML20FederationConfigOptions config)
        {
            string endpointId = Saml20PrincipalCache.GetSaml20AssertionLite().Issuer;
            if (string.IsNullOrEmpty(endpointId))
            {
                Trace.TraceData(TraceEventType.Information, Tracing.AttrQueryNoLogin);
                throw new InvalidOperationException(Tracing.AttrQueryNoLogin);
            }
            var ep = config.IDPEndPoints.FirstOrDefault(e => e.Id == endpointId);
            if (ep == null)
                throw new Saml20Exception($"Unable to find information about the IdP with id \"{endpointId}\"");
            await PerformQueryAsync(context, config, ep);
        }

        public async Task PerformQueryAsync(HttpContext context, SAML20FederationConfigOptions config, IDPEndPointOptions endPoint)
        {
            string nameIdFormat = Saml20PrincipalCache.GetSaml20AssertionLite().Subject.Format;
            if (string.IsNullOrEmpty(nameIdFormat))
                nameIdFormat = Saml20Constants.NameIdentifierFormats.Persistent;
            await PerformQueryAsync(context, config, endPoint, nameIdFormat);
        }

        public async Task PerformQueryAsync(HttpContext context, SAML20FederationConfigOptions config, IDPEndPointOptions endPoint, string nameIdFormat)
        {
            Trace.TraceMethodCalled(GetType(), "PerformQueryAsync()");
            NameID name = new NameID { Value = Saml20Identity.Current.Name, Format = nameIdFormat };
            _attrQuery.Subject.Items = new object[] { name };
            _attrQuery.SamlAttribute = _attributes.ToArray();
            XmlDocument query = new XmlDocument { XmlResolver = null };
            query.LoadXml(Serialization.SerializeToXmlString(_attrQuery));
            if (query.FirstChild is XmlDeclaration)
                query.RemoveChild(query.FirstChild);
            if (Trace.ShouldTrace(TraceEventType.Information))
                Trace.TraceData(TraceEventType.Information, $"Sending attribute query to {endPoint.SSOEndpoint.Url}, {query.OuterXml}");
            string soapEnvelope = new HttpSOAPBindingBuilder(context).WrapInSoapEnvelope(query.OuterXml);
            string responseXml;
            using (var httpClient = new HttpClient())
            {
                var content = new StringContent(soapEnvelope, System.Text.Encoding.UTF8, "text/xml");
                var response = await httpClient.PostAsync(endPoint.SSOEndpoint.Url, content);
                response.EnsureSuccessStatusCode();
                responseXml = await response.Content.ReadAsStringAsync();
            }
            // TODO: Parse responseXml, extract assertion, validate signature, etc.
            // You may need to update this logic to match your assertion parsing and validation needs.
        }

        public static Saml20AttributeQuery GetDefault(SAML20FederationConfigOptions config)
        {
            Saml20AttributeQuery result = new Saml20AttributeQuery();
            if (config.ServiceProvider == null || string.IsNullOrEmpty(config.ServiceProvider.Id))
                throw new Saml20FormatException(Resources.ServiceProviderNotSet);
            result.Issuer = config.ServiceProvider.Id;
            return result;
        }
    }

    public enum Saml20NameFormat
    {
        BASIC,
        URI,
    }
}