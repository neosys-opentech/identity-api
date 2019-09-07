using System;

namespace Identity.Domain.Results
{
    /// <summary>
    /// role result class
    /// </summary>
    public class RoleResult
    {
        /// <summary>
        /// gets or sets the role name
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// gets or sets the creation date
        /// </summary>
        public DateTime CreationDate { get; set; }

        /// <summary>
        /// gets or sets the update date
        /// </summary>
        public DateTime UpdateDate { get; set; }
    }
}
