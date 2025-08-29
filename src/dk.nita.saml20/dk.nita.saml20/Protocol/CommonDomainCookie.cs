using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using Microsoft.AspNetCore.Http;

namespace Identity.Saml.Protocol
{
    /// <summary>
    /// Implements access to the common domain cookie specified in the SAML20 identity provider discovery profile
    /// </summary>
    public class CommonDomainCookie
    {
        public const string COMMON_DOMAIN_COOKIE_NAME = "_saml_idp";

        private readonly IRequestCookieCollection? _requestCookies;
        private readonly string? _saml_idp;
        private bool _isLoaded = false;
        private bool _isSet = false;
        private readonly List<string> _knownIDPs;

        // Constructor for reading from cookies
        public CommonDomainCookie(IRequestCookieCollection requestCookies)
        {
            _requestCookies = requestCookies;
            _knownIDPs = new List<string>();
        }

        // Constructor for reading from a string value
        public CommonDomainCookie(string saml_idp)
        {
            _saml_idp = saml_idp;
            _knownIDPs = new List<string>();
        }

        public bool IsSet
        {
            get
            {
                Load();
                return _isSet;
            }
        }

        public List<string> KnownIDPs
        {
            get
            {
                EnsureSet();
                return _knownIDPs;
            }
        }

        public string PreferredIDP
        {
            get
            {
                EnsureSet();
                if (_knownIDPs.Count > 0)
                    return _knownIDPs[_knownIDPs.Count - 1];
                return string.Empty;
            }
        }

        private void EnsureSet()
        {
            Load();
            if (!_isSet)
                throw new Saml20Exception("The common domain cookie is not set. Please make sure to check the IsSet property before accessing the class' properties.");
        }

        private void Load()
        {
            if (_requestCookies != null)
                LoadCookie();
            if (!string.IsNullOrEmpty(_saml_idp))
                LoadFromString();
        }

        private void LoadFromString()
        {
            if (!_isLoaded)
            {
                ParseCookie(_saml_idp!);
                _isSet = true;
                _isLoaded = true;
            }
        }

        private void LoadCookie()
        {
            if (!_isLoaded)
            {
                if (_requestCookies!.TryGetValue(COMMON_DOMAIN_COOKIE_NAME, out var cookieValue))
                {
                    ParseCookie(cookieValue);
                    _isSet = true;
                }
                _isLoaded = true;
            }
        }

        private void ParseCookie(string rawValue)
        {
            string value = WebUtility.UrlDecode(rawValue);
            string[] idps = value.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string base64idp in idps)
            {
                byte[] bytes = Convert.FromBase64String(base64idp);
                string idp = Encoding.ASCII.GetString(bytes);
                _knownIDPs.Add(idp);
            }
        }
    }
}