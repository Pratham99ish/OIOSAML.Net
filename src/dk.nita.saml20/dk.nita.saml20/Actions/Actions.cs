using System.Collections.Generic;
using System;
using dk.nita.saml20.config;
using dk.nita.saml20.Configuration;

namespace dk.nita.saml20.Actions
{
    public class Actions
    {
        public static List<IAction> GetDefaultActions()
        {
            List<IAction> actions = new List<IAction>();
            actions.Add(new SamlPrincipalAction());
            actions.Add(new RedirectAction());
            return actions;
        }

        public static List<IAction> GetActions(FederationConfigOptions config)
        {
            List<IAction> actions = GetDefaultActions();
            if (config.Actions?.ActionList != null)
            {
                foreach (var ac in config.Actions.ActionList)
                {
                    // Use Name and Type properties for POCO config
                    if (string.Equals(ac.Type, "clear", StringComparison.OrdinalIgnoreCase))
                        actions.Clear();
                    else if (string.Equals(ac.Type, "remove", StringComparison.OrdinalIgnoreCase))
                        actions.RemoveAll(a => a.Name == ac.Name);
                    else if (!string.IsNullOrEmpty(ac.Type) && !string.Equals(ac.Type, "add", StringComparison.OrdinalIgnoreCase))
                    {
                        // For custom action types, instantiate by type name
                        IAction add = (IAction)Activator.CreateInstance(Type.GetType(ac.Type));
                        actions.Add(add);
                    }
                }
            }
            return actions;
        }
    }
}
