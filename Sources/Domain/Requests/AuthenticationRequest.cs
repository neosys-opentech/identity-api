namespace Identity.Domain.Requests
{
    /// <summary>
    /// Authentication request
    /// </summary>
    public class AuthenticationRequest
    {
        /// <summary>
        /// gets or sets the user login
        /// </summary>
        public string Login { get; set; }

        /// <summary>
        /// gets or sets the password
        /// </summary>
        public string Password { get; set; }
    }
}
