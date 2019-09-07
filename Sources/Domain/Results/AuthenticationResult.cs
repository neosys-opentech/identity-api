namespace Identity.Domain.Results
{
    /// <summary>
    /// gets or sets the authentication result
    /// </summary>
    public class AuthenticationResult : ResultMessage
    {
        /// <summary>
        /// gets or sets the token
        /// </summary>
        public string Token { get; set; }
    }
}
