using Dapper;
using Identity.Domain;
using Identity.Domain.Model;
using Identity.Infrastructure.Resources;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Identity.Infrastructure.Repositories
{
    /// <summary>
    /// users repository class
    /// </summary>
    public partial class UsersRepository : IUserRoleStore<User>
    {
        /// <inheritdoc />
        public async Task AddToRoleAsync(User user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            using (SqlConnection sqlConnection = new SqlConnection(_connectionString))
            {
                await sqlConnection.OpenAsync().ConfigureAwait(false);
                IdentityRole<int> role = await GetIdentityRoleAsync(sqlConnection, roleName).ConfigureAwait(false);

                if (role == null)
                {
                    throw new InvalidOperationException(string.Format(MessageResources.AssignInexistantRoleToUser, user.UserName));
                }
                
                DynamicParameters dynamicParameters = new DynamicParameters();
                dynamicParameters.Add("@UserId", user.Id);
                dynamicParameters.Add("@RoleId", role.Id);
                await sqlConnection.ExecuteAsync("ps_AspNetUserRoles_i", dynamicParameters, commandType: CommandType.StoredProcedure).ConfigureAwait(false);
            }
        }

        /// <inheritdoc />
        public async Task<IList<string>> GetRolesAsync(User user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            using (SqlConnection sqlConnection = new SqlConnection(_connectionString))
            {
                await sqlConnection.OpenAsync().ConfigureAwait(false);
                DynamicParameters dynamicParameters = new DynamicParameters();
                dynamicParameters.Add("@UserId", user.Id);
                IEnumerable<IdentityRole<int>> identityRoles = await sqlConnection.QueryAsync<IdentityRole<int>>(
                    Constants.PS_AspNetRoles_SelectByUserId, dynamicParameters, commandType: CommandType.StoredProcedure).ConfigureAwait(false);
                return identityRoles?.Select(r => r.NormalizedName).ToList();
            }
        }

        /// <inheritdoc />
        public async Task<IList<User>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (SqlConnection sqlConnection = new SqlConnection(_connectionString))
            {
                await sqlConnection.OpenAsync().ConfigureAwait(false);
                IdentityRole<int> role = await GetIdentityRoleAsync(sqlConnection, roleName).ConfigureAwait(false);

                if (role == null)
                {
                    throw new InvalidOperationException(string.Format(MessageResources.GetUsersInsideInexistantRole, roleName));
                }

                
                DynamicParameters dynamicParameters = new DynamicParameters();
                dynamicParameters.Add("@RoleId", role.Id);
                IEnumerable<User> users = await sqlConnection.QueryAsync<User>(Constants.PS_AspNetUsers_SelectByRoleId,
                    dynamicParameters, commandType: CommandType.StoredProcedure).ConfigureAwait(false);
                return users?.ToList();
            }
        }

        /// <inheritdoc />
        public async Task<bool> IsInRoleAsync(User user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            using (SqlConnection sqlConnection = new SqlConnection(_connectionString))
            {
                await sqlConnection.OpenAsync().ConfigureAwait(false);
                IdentityRole<int> role = await GetIdentityRoleAsync(sqlConnection, roleName).ConfigureAwait(false);

                if (role == null)
                {
                    throw new InvalidOperationException(string.Format(MessageResources.VerifyUserBelongsToInexistantRole, user.UserName, roleName));
                }

                DynamicParameters dynamicParameters = new DynamicParameters();
                dynamicParameters.Add("@RoleId", role.Id);
                dynamicParameters.Add("@UserId", user.Id);
                IdentityUserRole<int> userRole = await sqlConnection.QueryFirstOrDefaultAsync<IdentityUserRole<int>>(Constants.PS_AspNetUserRoles_SelectByRoleIdAndUserId,
                    dynamicParameters, commandType: CommandType.StoredProcedure).ConfigureAwait(false);
                return userRole != null;
            }
        }

        /// <inheritdoc />
        public async Task RemoveFromRoleAsync(User user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            using (SqlConnection sqlConnection = new SqlConnection(_connectionString))
            {
                await sqlConnection.OpenAsync().ConfigureAwait(false);
                IdentityRole<int> role = await GetIdentityRoleAsync(sqlConnection, roleName).ConfigureAwait(false);

                if (role == null)
                {
                    throw new InvalidOperationException(string.Format(MessageResources.RemoveUserFromInexistantRole, user.UserName, roleName));
                }

                DynamicParameters dynamicParameters = new DynamicParameters();
                dynamicParameters.Add("@RoleId", role.Id);
                dynamicParameters.Add("@UserId", user.Id);
                await sqlConnection.ExecuteAsync(Constants.PS_AspNetUserRoles_Delete, dynamicParameters, commandType: CommandType.StoredProcedure).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Get identity role by role name
        /// </summary>
        /// <param name="roleName">identity role name</param>
        /// <param name="sqlConnection">sql connection instance</param>
        /// <returns>identity role object</returns>
        private async Task<IdentityRole<int>> GetIdentityRoleAsync(SqlConnection sqlConnection, string roleName)
        {
            DynamicParameters dynamicParameters = new DynamicParameters();
            dynamicParameters.Add("@NormalizedName", roleName);
            return await sqlConnection.QueryFirstOrDefaultAsync<IdentityRole<int>>(Constants.PS_AspNetRoles_SelectByNormalizedName,
                dynamicParameters, commandType: CommandType.StoredProcedure).ConfigureAwait(false);
        }
    }
}
