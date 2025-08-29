using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;

namespace Identity.Saml.Logging
{
    /// <summary>
    /// An implementation of the IAuditLogger interface that uses the System.Diagnostics Trace functionality to audit log.
    /// </summary>
    class TraceAuditLogger : IAuditLogger
    {
        /// <summary>
        /// The source to use for logging
        /// </summary>
        private readonly static TraceSource _source;

        static TraceAuditLogger()
        {
            _source = new TraceSource("Identity.Saml.auditLogger");
        }

        public void LogEntry(string msg, string data, string userHostAddress, string idpId, string assertionId, string sessionId, string direction, string operation)
        {
            if (_source.Switch.ShouldTrace(TraceEventType.Information))
            {
                var str = String.Format("Session id: {5}, Direction: {6}, Operation: {7}, User IP: {2}, Idp ID: {3}, Assertion ID: {4}, Message: {0}, Data: {1}", msg, data ?? "", userHostAddress, idpId, assertionId, sessionId, direction, operation);
                _source.TraceData(TraceEventType.Information, 0, str);
            }
        }
    }
}
