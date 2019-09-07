using System.Collections.Generic;

namespace Identity.Domain.Results
{
    /// <summary>
    /// roles list message
    /// </summary>
    public class RolesListMessage : ResultMessage
    {
        /// <summary>
        /// gets or sets the roles list
        /// </summary>
        public IEnumerable<RoleResult> Roles { get; set; }
    }
}
