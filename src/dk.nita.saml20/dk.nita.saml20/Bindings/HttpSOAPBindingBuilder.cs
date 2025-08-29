using Microsoft.AspNetCore.Http;
using System.IO;
using System.Text;
using dk.nita.saml20.config;

namespace dk.nita.saml20.Bindings
{
    /// <summary>
    /// Implements the HTTP SOAP binding
    /// </summary>
    public class HttpSOAPBindingBuilder
    {
        /// <summary>
        /// The current http context
        /// </summary>
        protected HttpContext _context;

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpSOAPBindingBuilder"/> class.
        /// </summary>
        /// <param name="context">The current HTTP context.</param>
        public HttpSOAPBindingBuilder(HttpContext context)
        {
            _context = context;
        }

        /// <summary>
        /// Sends a response message.
        /// </summary>
        /// <param name="samlMessage">The saml message.</param>
        public void SendResponseMessage(string samlMessage)
        {
            _context.Response.ContentType = "text/xml";
            using (var writer = new StreamWriter(_context.Response.Body))
            {
                writer.Write(WrapInSoapEnvelope(samlMessage));
                writer.Flush();
            }
            // In ASP.NET Core, you typically do not call Response.End()
        }

        /// <summary>
        /// Wraps a message in a SOAP envelope.
        /// </summary>
        /// <param name="s">The s.</param>
        /// <returns></returns>
        public string WrapInSoapEnvelope(string s)
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine(SOAPConstants.EnvelopeBegin);
            builder.AppendLine(SOAPConstants.BodyBegin);
            builder.AppendLine(s);
            builder.AppendLine(SOAPConstants.BodyEnd);
            builder.AppendLine(SOAPConstants.EnvelopeEnd);

            return builder.ToString();
        }

        // NOTE: WCF SOAP client code removed for .NET 8 compatibility. If SOAP client is needed, use HttpClient or a third-party library.
    }
}