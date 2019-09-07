namespace Identity.Domain.Requests
{
    /// <summary>
    /// user role assignment request
    /// </summary>
    public class UserRoleAssignmentRequest
    {
        /// <summary>
        /// gets or sets role name
        /// </summary>
        public string RoleName { get; set; }

        /// <summary>
        /// gets or sets the user login
        /// </summary>
        public string Login { get; set; }
    }
}
