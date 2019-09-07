using Microsoft.AspNetCore.Identity;
using System;

namespace Identity.Domain.Model
{
    /// <summary>
    /// user class
    /// </summary>
    public class User : IdentityUser<int>
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
