using System;

namespace dk.nita.saml20.config
{
    /// <summary>
    /// POCO for legacy IDPEndPointElement, compatible with HttpPostBindingBuilder.
    /// </summary>
    public class IDPEndPointElement
    {
        public string Url { get; set; }
        public string Binding { get; set; }
        public string ForceProtocolBinding { get; set; }
        public string IdpTokenAccessor { get; set; }
    }
}
