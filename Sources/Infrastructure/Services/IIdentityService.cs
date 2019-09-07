using Identity.Domain.Requests;
using Identity.Domain.Results;
using System.Threading.Tasks;

namespace Identity.Infrastructure.Services
{
    /// <summary>
    /// identity service interface
    /// </summary>
    public interface IIdentityService
    {
        /// <summary>
        /// Authenticate users
        /// </summary>
        /// <param name="request">authentication request</param>
        /// <returns>authentication result</returns>
        Task<AuthenticationResult> AuthenticateUserAsync(AuthenticationRequest request);

        /// <summary>
        /// creates a new user
        /// </summary>
        /// <param name="request">user creation request</param>
        /// <returns>result message</returns>
        Task<ResultMessage> CreateUserAsync(UserCreationRequest request);

        /// <summary>
        /// deletes a user
        /// </summary>
        /// <param name="request">delete user request</param>
        /// <returns>result message</returns>
        Task<ResultMessage> DeleteUserAsync(DeleteUserRequest request);

        /// <summary>
        /// assigns role to a specific user
        /// </summary>
        /// <param name="request">user role assignment request</param>
        /// <returns>result message</returns>
        Task<ResultMessage> AssignRoleToUserAsync(UserRoleAssignmentRequest request);

        /// <summary>
        /// unassigns a user from a role
        /// </summary>
        /// <param name="request">user role assignment request</param>
        /// <returns>result message</returns>
        Task<ResultMessage> UnassignRoleToUserAsync(UserRoleAssignmentRequest request);

        /// <summary>
        /// Initialize a user's password
        /// </summary>
        /// <param name="request">request object</param>
        /// <returns>result message</returns>
        Task<ResultMessage> InitializeUserPasswordAsync(PasswordInitializationRequest request);

        /// <summary>
        /// update a user's password
        /// </summary>
        /// <param name="request">request object</param>
        /// <returns>result message</returns>
        Task<ResultMessage> UpdateUserPasswordAsync(PasswordInitializationRequest request);

        /// <summary>
        /// gets all users
        /// </summary>
        UsersListMessage Users { get; }

        /// <summary>
        /// gets all roles
        /// </summary>
        RolesListMessage Roles { get; }
    }
}
