namespace Identity.Domain.Requests
{
    /// <summary>
    /// password initialization request class
    /// </summary>
    public class PasswordInitializationRequest
    {
        /// <summary>
        /// gets or sets the user login
        /// </summary>
        public string Login { get; set; }

        /// <summary>
        /// gets or sets the user old password
        /// </summary>
        public string OldPassword { get; set; }

        /// <summary>
        /// gets or sets the user new password
        /// </summary>
        public string NewPassword { get; set; }
    }
}
