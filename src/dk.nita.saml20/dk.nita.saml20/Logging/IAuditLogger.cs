using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Identity.Saml.Logging
{
    /// <summary>
    /// Defines the behaviour of an audit logger that logs an audit trail
    /// </summary>
    public interface IAuditLogger
    {
        /// <summary>
        /// Logs the record
        /// </summary>
        /// <param name="msg">The message to log</param>
        /// <param name="data">Extra data to log</param>
        /// <param name="userHostAddress">The ip address of the user</param>
        /// <param name="idpId">The id of the idp</param>
        /// <param name="assertionId">The id of the assertion</param>
        /// <param name="sessionId">The id of the session</param>
        /// <param name="direction">The direction (in/out)</param>
        /// <param name="operation">The operation (e.g. login, logout, discover, etc.)</param>
        void LogEntry(string msg, string data, string userHostAddress, string idpId, string assertionId, string sessionId, string direction, string operation);
    }
}
