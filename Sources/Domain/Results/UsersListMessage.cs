using System.Collections.Generic;

namespace Identity.Domain.Results
{
    /// <summary>
    /// users list message class
    /// </summary>
    public class UsersListMessage : ResultMessage
    {
        /// <summary>
        /// gets or sets the users
        /// </summary>
        public IEnumerable<UserResult> Users { get; set; }
    }
}
