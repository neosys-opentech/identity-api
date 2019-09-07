using Microsoft.AspNetCore.Identity;
using System;

namespace Identity.Domain.Model
{
    /// <summary>
    /// role class
    /// </summary>
    public class Role : IdentityRole<int>
    {
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
