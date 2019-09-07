namespace Identity.Domain.Requests
{
    /// <summary>
    /// user creation request class
    /// </summary>
    public class UserCreationRequest
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
        /// gets or sets the user password
        /// </summary>
        public string Password { get; set; }
    }
}
