using System.Xml.Serialization;

namespace Identity.Saml.Schema.Protocol
{
    /// <summary>
    /// The AppSwitchPlatform contains the platforms available for app switching.
    /// </summary>
    public enum AppSwitchPlatform
    {
        /// <summary>
        /// iOS Platform
        /// </summary>
        [XmlEnum(Name="iOS")]
        iOS,
        
        /// <summary>
        /// Android platform
        /// </summary>
        [XmlEnum(Name="Android")]
        Android
    }
}