using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Identity.Saml.config;
using Identity.Saml.Configuration;
using Identity.Saml.Schema.Core;
using Identity.Saml.Schema.Metadata;
using Identity.Saml.Schema.XmlDSig;
using Identity.Saml.Utils;
using Identity.Saml.Bindings.SignatureProviders;
using System.Linq;
using Endpoint = Identity.Saml.Schema.Metadata.Endpoint;
using IDPEndPointElement = Identity.Saml.Schema.Metadata.IDPEndPointElement;

namespace Identity.Saml
{
    /// <summary>
    /// The Saml20MetadataDocument class handles functionality related to the &lt;EntityDescriptor&gt; element.
    /// If a received metadata document contains a &lt;EntitiesDescriptor&gt; element, it is necessary to use an
    /// instance of this class for each &lt;EntityDescriptor&gt; contained.
    /// </summary>
    public class Saml20MetadataDocument
    {
        #region Constructors.
        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20MetadataDocument"/> class.
        /// </summary>
        public Saml20MetadataDocument()
        { }

        /// <summary>
        /// Initialize the instance with an already existing metadata document.
        /// </summary>        
        public Saml20MetadataDocument(XmlDocument entityDescriptor)
            : this()
        {
            if (XmlSignatureUtils.IsSigned(entityDescriptor))
                if (!XmlSignatureUtils.CheckSignature(entityDescriptor))
                    throw new Saml20Exception("Metadata signature could not be verified.");

            ExtractKeyDescriptors(entityDescriptor);
            _entity = Serialization.DeserializeFromXmlString<EntityDescriptor>(entityDescriptor.OuterXml);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20MetadataDocument"/> class.
        /// </summary>
        /// <param name="sign">if set to <c>true</c> the metadata document will be signed.</param>
        public Saml20MetadataDocument(bool sign)
            : this()
        {
            Sign = sign;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml20MetadataDocument"/> class.
        /// </summary>
        /// <param name="config">The config.</param>
        /// <param name="keyinfos">key information for the service provider certificates.</param>
        /// <param name="sign">if set to <c>true</c> the metadata document will be signed.</param>
        public Saml20MetadataDocument(SAML20FederationConfig config, IEnumerable<Identity.Saml.Schema.XmlDSig.KeyInfo> keyinfos, bool sign)
            : this(sign)
        {
            ConvertToMetadata(config, keyinfos);
        }
        #endregion

        /// <summary>
        /// Takes the Safewhere configuration class and converts it to a SAML2.0 metadata document.
        /// </summary>        
        private void ConvertToMetadata(SAML20FederationConfig config, IEnumerable<Schema.XmlDSig.KeyInfo> keyinfos)
        {
            var entity = CreateDefaultEntity();
            entity.entityID = config.ServiceProvider.Id;
            entity.validUntil = DateTime.Now.AddDays(7);

            var spDescriptor = new SPSSODescriptor();
            spDescriptor.protocolSupportEnumeration = new string[] { Saml20Constants.PROTOCOL };
            spDescriptor.AuthnRequestsSigned = XmlConvert.ToString(true);
            spDescriptor.WantAssertionsSigned = XmlConvert.ToString(true);

            var baseURL = config.ServiceProvider.Server;
            var logoutServiceEndpoints = new List<Endpoint>();
            var signonServiceEndpoints = new List<IndexedEndpoint>();
            var artifactResolutionEndpoints = new List<IndexedEndpoint>(2);

            foreach (var endpoint in config.ServiceProvider.ServiceEndpoints)
            {
                switch (endpoint.Type)
                {
                    case "SIGNON":
                        var loginEndpoint = new IndexedEndpoint
                        {
                            index = endpoint.EndPointIndex,
                            isDefault = true,
                            Location = baseURL + endpoint.LocalPath,
                            Binding = GetBinding(endpoint.Binding, Saml20Constants.ProtocolBindings.HTTP_Post)
                        };
                        signonServiceEndpoints.Add(loginEndpoint);

                        var artifactSignonEndpoint = new IndexedEndpoint
                        {
                            Binding = Saml20Constants.ProtocolBindings.HTTP_SOAP,
                            index = loginEndpoint.index,
                            Location = loginEndpoint.Location
                        };
                        artifactResolutionEndpoints.Add(artifactSignonEndpoint);
                        break;
                    case "LOGOUT":
                        var logoutEndpointPost = new Endpoint
                        {
                            Location = baseURL + endpoint.LocalPath,
                            ResponseLocation = baseURL + endpoint.LocalPath,
                            Binding = GetBinding(endpoint.Binding, Saml20Constants.ProtocolBindings.HTTP_Post)
                        };
                        logoutServiceEndpoints.Add(logoutEndpointPost);

                        var logoutEndpointRedirect = new Endpoint
                        {
                            Location = baseURL + endpoint.LocalPath,
                            ResponseLocation = baseURL + endpoint.LocalPath,
                            Binding = GetBinding(endpoint.Binding, Saml20Constants.ProtocolBindings.HTTP_Redirect)
                        };
                        logoutServiceEndpoints.Add(logoutEndpointRedirect);

                        var artifactLogoutEndpoint = new IndexedEndpoint
                        {
                            Binding = Saml20Constants.ProtocolBindings.HTTP_SOAP,
                            index = endpoint.EndPointIndex,
                            Location = logoutEndpointRedirect.Location
                        };
                        artifactResolutionEndpoints.Add(artifactLogoutEndpoint);
                        break;
                    case "SOAPLOGOUT":
                        var logoutEndpointSoap = new Endpoint
                        {
                            Location = baseURL + endpoint.LocalPath,
                            ResponseLocation = baseURL + endpoint.LocalPath,
                            Binding = GetBinding(endpoint.Binding, Saml20Constants.ProtocolBindings.HTTP_SOAP)
                        };
                        logoutServiceEndpoints.Add(logoutEndpointSoap);
                        break;
                }
            }

            spDescriptor.SingleLogoutService = logoutServiceEndpoints.ToArray();
            spDescriptor.AssertionConsumerService = signonServiceEndpoints.ToArray();

            if (!string.IsNullOrEmpty(config.NameIdFormat))
            {
                spDescriptor.NameIDFormat = new string[] { config.NameIdFormat };
            }

            if (config.RequestedAttributes.Attributes.Count > 0)
            {
                var attConsumingService = new AttributeConsumingService();
                spDescriptor.AttributeConsumingService = new AttributeConsumingService[] { attConsumingService };
                attConsumingService.index = signonServiceEndpoints[0].index;
                attConsumingService.isDefault = true;
                attConsumingService.ServiceName = new LocalizedName[] { new LocalizedName("SP", "da") };

                attConsumingService.RequestedAttribute = new RequestedAttribute[config.RequestedAttributes.Attributes.Count];
                for (int i = 0; i < config.RequestedAttributes.Attributes.Count; i++)
                {
                    attConsumingService.RequestedAttribute[i] = new RequestedAttribute();
                    attConsumingService.RequestedAttribute[i].Name = config.RequestedAttributes.Attributes[i].Name;
                    if (config.RequestedAttributes.Attributes[i].IsRequired)
                        attConsumingService.RequestedAttribute[i].isRequired = true;
                    attConsumingService.RequestedAttribute[i].NameFormat = SamlAttribute.NAMEFORMAT_URI;
                }
            }
            else
            {
                spDescriptor.AttributeConsumingService = new AttributeConsumingService[0];
            }

            if (config.Metadata != null && config.Metadata.IncludeArtifactEndpoints)
                spDescriptor.ArtifactResolutionService = artifactResolutionEndpoints.ToArray();

            entity.Items = new object[] { spDescriptor };

            var KeyDescriptors = new List<KeyDescriptor>();
            foreach (var keyinfo in keyinfos)
            {
                var keySigning = new KeyDescriptor();
                var keyEncryption = new KeyDescriptor();
                KeyDescriptors.Add(keySigning);
                KeyDescriptors.Add(keyEncryption);

                keySigning.use = KeyTypes.signing;
                keySigning.useSpecified = true;

                keyEncryption.use = KeyTypes.encryption;
                keyEncryption.useSpecified = true;
                keyEncryption.EncryptionMethod = new []
                {
                    new Schema.XEnc.EncryptionMethod{Algorithm = Saml20Constants.CryptographicAlgorithm.Aes256Cbc},
                    new Schema.XEnc.EncryptionMethod{Algorithm = Saml20Constants.CryptographicAlgorithm.RsaOaepMgf1p}
                };

                // TODO: Map keyinfo to Schema.XmlDSig.KeyInfo if needed
                keySigning.KeyInfo = Serialization.DeserializeFromXmlString<Schema.XmlDSig.KeyInfo>(keyinfo.ToString());
                keyEncryption.KeyInfo = keySigning.KeyInfo;
            }
            spDescriptor.KeyDescriptor = KeyDescriptors.ToArray();

            // Organization mapping
            if (config.ServiceProvider.Organization != null)
            {
                entity.Organization = new Organization
                {
                    OrganizationName = new LocalizedName[] { new LocalizedName(config.ServiceProvider.Organization.Name, "en") },
                    OrganizationDisplayName = new LocalizedName[] { new LocalizedName(config.ServiceProvider.Organization.DisplayName, "en") },
                    OrganizationURL = new LocalizedURI[] { new LocalizedURI(config.ServiceProvider.Organization.Url, "en") }
                };
            }
            // ContactPerson mapping
            if (config.ServiceProvider.ContactPerson != null && config.ServiceProvider.ContactPerson.Count > 0)
            {
                entity.ContactPerson = config.ServiceProvider.ContactPerson
                    .Select(c => new Contact
                    {
                        // Map properties as needed
                        // Type, Company, GivenName, SurName, EmailAddress, TelephoneNumber
                    })
                    .ToArray();
            }
        }

        private string GetBinding(string samlBinding, string defaultValue)
        {
            switch (samlBinding)
            {
                case Saml20Constants.ProtocolBindings.HTTP_Artifact:
                    return Saml20Constants.ProtocolBindings.HTTP_Artifact;
                case Saml20Constants.ProtocolBindings.HTTP_Post:
                    return Saml20Constants.ProtocolBindings.HTTP_Post;
                case Saml20Constants.ProtocolBindings.HTTP_Redirect:
                    return Saml20Constants.ProtocolBindings.HTTP_Redirect;
                case Saml20Constants.ProtocolBindings.HTTP_SOAP:
                    return Saml20Constants.ProtocolBindings.HTTP_SOAP;
                default:
                    return defaultValue;
            }
        }

        /// <summary>
        /// Extract KeyDescriptors from the metadata document represented by this instance.
        /// </summary>
        private void ExtractKeyDescriptors()
        {
            if (_keys != null)
                return;

            if (_entity != null)
            {
                _keys = new List<KeyDescriptor>();
                foreach (object item in _entity.Items)
                {
                    if (item is RoleDescriptor)
                    {
                        RoleDescriptor rd = (RoleDescriptor)item;
                        foreach (KeyDescriptor keyDescriptor in rd.KeyDescriptor)
                            _keys.Add(keyDescriptor);
                    }
                }
            }
        }

        /// <summary>
        /// Retrieves the key descriptors contained in the document
        /// </summary>
        private void ExtractKeyDescriptors(XmlDocument doc)
        {
            XmlNodeList list = doc.GetElementsByTagName(KeyDescriptor.ELEMENT_NAME, Saml20Constants.METADATA);
            _keys = new List<KeyDescriptor>(list.Count);

            foreach (XmlNode node in list)
                _keys.Add(Serialization.DeserializeFromXmlString<KeyDescriptor>(node.OuterXml));
        }

        #region Properties

        private List<KeyDescriptor> _keys;

        /// <summary>
        /// The keys contained in the metadata document.
        /// </summary>
        public List<KeyDescriptor> Keys
        {
            get
            {
                if (_keys == null)
                    ExtractKeyDescriptors();

                return _keys;
            }
        }

        private Dictionary<ushort, IndexedEndpoint> _ARSEndpoints;
        private List<IDPEndPointElement> _SSOEndpoints;
        private List<IDPEndPointElement> _SLOEndpoints;
        private List<IDPEndPointElement> _AssertionConsumerServiceEndpoints;
        private List<Endpoint> _attributeQueryEndpoints;

        /// <summary>
        /// The SSO endpoints
        /// </summary>
        /// <returns></returns>
        public List<IDPEndPointElement> SSOEndpoints()
        {
            if (_SSOEndpoints == null)
                ExtractEndpoints();

            return _SSOEndpoints;
        }

        /// <summary>
        /// The SLO endpoints.
        /// </summary>
        /// <returns></returns>
        public List<IDPEndPointElement> SLOEndpoints()
        {
            if (_SLOEndpoints == null)
                ExtractEndpoints();

            return _SLOEndpoints;
        }

        /// <summary>
        /// Get the first SLO endpoint that supports the given binding.
        /// </summary>        
        /// <returns>The endpoint or <c>null</c> if metadata does not have an SLO endpoint with the given binding.</returns>
        public IDPEndPointElement SLOEndpoint(string binding)
        {
            return SLOEndpoints().Find(endp => endp.Binding == binding);
        }

        /// <summary>
        /// Get the first SSO endpoint that supports the given binding.
        /// </summary>        
        /// <returns>The endpoint or <c>null</c> if metadata does not have an SSO endpoint with the given binding.</returns>
        public IDPEndPointElement SSOEndpoint(string binding)
        {
            return SSOEndpoints().Find(endp => endp.Binding == binding);
        }



        /// <summary>
        /// Contains the endpoints specified in the &lt;AssertionConsumerService&gt; element in the SPSSODescriptor.
        /// These endpoints are only applicable if we are reading metadata issued by a service provider.
        /// </summary>
        /// <returns></returns>
        public List<IDPEndPointElement> AssertionConsumerServiceEndpoints()
        {
            if (_AssertionConsumerServiceEndpoints == null)
                ExtractEndpoints();

            return _AssertionConsumerServiceEndpoints;
        }

        private void ExtractEndpoints()
        {
            if (_entity != null)
            {
                _SSOEndpoints = new List<IDPEndPointElement>();
                _SLOEndpoints = new List<IDPEndPointElement>();
                _ARSEndpoints = new Dictionary<ushort, IndexedEndpoint>();
                _AssertionConsumerServiceEndpoints = new List<IDPEndPointElement>();
                _attributeQueryEndpoints = new List<Endpoint>();

                foreach (object item in _entity.Items)
                {
                    if (item is IDPSSODescriptor)
                    {
                        IDPSSODescriptor descriptor = (IDPSSODescriptor)item;
                        foreach (Endpoint endpoint in descriptor.SingleSignOnService)
                            _SSOEndpoints.Add(new IDPEndPointElement(endpoint));
                    }

                    if (item is SSODescriptor ssoDescriptor)
                    {
                        if (ssoDescriptor.SingleLogoutService != null)
                        {
                            foreach (Endpoint endpoint in ssoDescriptor.SingleLogoutService)
                                _SLOEndpoints.Add(new IDPEndPointElement(endpoint));
                        }

                        if (ssoDescriptor.ArtifactResolutionService != null)
                        {
                            foreach (IndexedEndpoint ie in ssoDescriptor.ArtifactResolutionService)
                            {
                                _ARSEndpoints.Add(ie.index, ie);
                            }
                        }
                    }

                    if (item is SPSSODescriptor spDescriptor)
                    {
                        foreach (IndexedEndpoint endpoint in spDescriptor.AssertionConsumerService)
                            _AssertionConsumerServiceEndpoints.Add(new IDPEndPointElement(endpoint));
                    }

                    if (item is AttributeAuthorityDescriptor aad)
                    {
                        _attributeQueryEndpoints.AddRange(aad.AttributeService.ToList());
                    }
                }
            }
        }

        /// <summary>
        /// Retrieves the keys marked with the usage given as parameter.
        /// </summary>
        /// <returns>A list containing the keys. If no key is marked with the given usage, the method returns an empty list.</returns>
        public List<KeyDescriptor> GetKeys(KeyTypes usage)
        {
            return Keys.FindAll(delegate (KeyDescriptor desc) { return desc.use == usage; });
        }

        /// <summary>
        /// The ID of the entity described in the document.
        /// </summary>
        public string EntityId
        {
            get
            {
                if (_entity != null)
                    return _entity.entityID;

                throw new InvalidOperationException("This instance does not contain a metadata document");
            }
        }

        /// <summary>
        /// Determines whether the metadata should be signed when the ToXml() method is called.
        /// </summary>
        public bool Sign;

        private EntityDescriptor _entity;
        /// <summary>
        /// Gets the entity.
        /// </summary>
        /// <value>The entity.</value>
        public EntityDescriptor Entity
        {
            get { return _entity; }
        }

        #endregion

        /// <summary>
        /// Return a string containing the metadata XML based on the settings added to this instance.
        /// The resulting XML will be signed, if the AsymmetricAlgoritm property has been set.
        /// The default encoding (UTF-8) will be used for the resulting XML.
        /// </summary>
        /// <returns></returns>
        public string ToXml()
        {
            return ToXml(Encoding.UTF8);
        }

        /// <summary>
        /// Gets the ArtifactResolutionService endpoint.
        /// </summary>
        /// <param name="index">The index.</param>
        /// <returns></returns>
        public string GetARSEndpoint(ushort index)
        {
            IndexedEndpoint ep = _ARSEndpoints[index];
            if (ep != null)
            {
                return ep.Location;
            }

            return string.Empty;
        }

        /// <summary>
        /// Gets the location of the first AttributeQuery endpoint.
        /// </summary>
        /// <returns></returns>
        public string GetAttributeQueryEndpointLocation()
        {
            List<Endpoint> endpoints = GetAttributeQueryEndpoints();

            if (endpoints.Count == 0)
                throw new Saml20Exception("The identity provider does not support attribute queries.");

            return endpoints[0].Location;
        }

        /// <summary>
        /// Gets all AttributeQuery endpoints.
        /// </summary>
        /// <returns></returns>
        public List<Endpoint> GetAttributeQueryEndpoints()
        {
            if (_attributeQueryEndpoints == null)
            {
                ExtractEndpoints();
            }

            return _attributeQueryEndpoints;
        }

        /// <summary>
        /// Return a string containing the metadata XML based on the settings added to this instance.
        /// The resulting XML will be signed, if the AsymmetricAlgoritm property has been set.
        /// </summary>
        public string ToXml(Encoding enc)
        {
            XmlDocument doc = new XmlDocument();
            doc.XmlResolver = null;
            doc.PreserveWhitespace = true;

            doc.LoadXml(Serialization.SerializeToXmlString(_entity));

            // Add the correct encoding to the head element.
            if (doc.FirstChild is XmlDeclaration)
                ((XmlDeclaration)doc.FirstChild).Encoding = enc.WebName;
            else
                doc.PrependChild(doc.CreateXmlDeclaration("1.0", enc.WebName, null));

            return doc.OuterXml;
        }

        /// <summary>
        /// Creates a default entity in the 
        /// </summary>
        /// <returns></returns>
        public EntityDescriptor CreateDefaultEntity()
        {
            if (_entity != null)
                throw new InvalidOperationException("An entity is already created in this document.");
            _entity = GetDefaultEntityInstance();
            return _entity;
        }

        private static EntityDescriptor GetDefaultEntityInstance()
        {
            EntityDescriptor result = new EntityDescriptor();
            result.ID = "id" + Guid.NewGuid().ToString("N");
            return result;
        }
    }
}

