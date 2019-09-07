using System;

namespace Identity.Domain.Results
{
    /// <summary>
    /// user result class
    /// </summary>
    public class UserResult
    {
        /// <summary>
        /// gets or sets the user login
        /// </summary>
        public string Login { get; set; }

        /// <summary>
        /// gets or sets the user email
        /// </summary>
        public string Email { get; set; }

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
