using System;
using System.Collections.Generic;
using System.Diagnostics;
using Identity.Saml.config;
using Trace=Identity.Saml.Utils.Trace;
using Identity.Saml.Configuration;

namespace Identity.Saml.Specification
{
    ///<summary>
    /// 
    ///</summary>
    public class SpecificationFactory
    {
        /// <summary>
        /// Gets the certificate specifications.
        /// </summary>
        /// <param name="endpoint">The endpoint.</param>
        /// <returns>A list of certificate validation specifications for this endpoint</returns>
        public static List<ICertificateSpecification> GetCertificateSpecifications(IDPEndPointOptions endpoint)
        {
            List<ICertificateSpecification> specs = new List<ICertificateSpecification>();

            if(endpoint.CertificateValidation != null && endpoint.CertificateValidation.CertificateValidations != null &&
                endpoint.CertificateValidation.CertificateValidations.Count > 0)
            {
                foreach(var elem in endpoint.CertificateValidation.CertificateValidations)
                {
                    try
                    {
                        ICertificateSpecification val = (ICertificateSpecification) Activator.CreateInstance(Type.GetType(elem.Type));
                        specs.Add(val);
                    }catch(Exception e)
                    {
                        Trace.TraceData(TraceEventType.Error, e.ToString());
                    }
                }
            }

            if(specs.Count == 0)
            {
                //Add default specification
                specs.Add(new DefaultCertificateSpecification());
            }

            return specs;
        }
    }
    
}
