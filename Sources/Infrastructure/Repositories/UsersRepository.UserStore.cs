using Dapper;
using Identity.Domain;
using Identity.Domain.Model;
using Identity.Infrastructure.Assemblers;
using Identity.Infrastructure.Resources;
using Microsoft.AspNetCore.Identity;
using System;
using System.Data;
using System.Data.SqlClient;
using System.Threading;
using System.Threading.Tasks;

namespace Identity.Infrastructure.Repositories
{
    /// <summary>
    /// Users repository class
    /// </summary>
    public partial class UsersRepository : IUserStore<User>
    {
        /// <inheritdoc />
        public async Task<IdentityResult> CreateAsync(User user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            using (SqlConnection sqlConnection = new SqlConnection(_connectionString))
            {
                await sqlConnection.OpenAsync().ConfigureAwait(false);
                user.Id = await sqlConnection.ExecuteScalarAsync<int>(Constants.PS_AspNetUsers_Insert, user.ToDynamicParameters(), commandType: CommandType.StoredProcedure)
                    .ConfigureAwait(false);
                return IdentityResult.Success;
            }
        }

        /// <inheritdoc />
        public async Task<IdentityResult> DeleteAsync(User user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (SqlConnection sqlConnection = new SqlConnection(_connectionString))
            {
                await sqlConnection.OpenAsync().ConfigureAwait(false);
                DynamicParameters dynamicParameters = new DynamicParameters();
                dynamicParameters.Add("@Id", user.Id);
                await sqlConnection.ExecuteAsync(Constants.PS_AspNetUsers_Delete, dynamicParameters, commandType: CommandType.StoredProcedure)
                    .ConfigureAwait(false);
                return IdentityResult.Success;
            }
        }

        /// <inheritdoc />
        public async Task<User> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!int.TryParse(userId, out int parsedUserId))
            {
                throw new FormatException(string.Format(MessageResources.ValueNotInteger, nameof(userId)));
            }

            using (SqlConnection sqlConnection = new SqlConnection(_connectionString))
            {
                await sqlConnection.OpenAsync().ConfigureAwait(false);
                DynamicParameters dynamicParameters = new DynamicParameters();
                dynamicParameters.Add("@Id", parsedUserId);
                return await sqlConnection.QueryFirstOrDefaultAsync<User>(Constants.PS_AspNetUsers_SelectById, dynamicParameters, commandType: CommandType.StoredProcedure)
                    .ConfigureAwait(false);
            }
        }

        /// <inheritdoc />
        public async Task<User> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (SqlConnection sqlConnection = new SqlConnection(_connectionString))
            {
                await sqlConnection.OpenAsync().ConfigureAwait(false);
                DynamicParameters dynamicParameters = new DynamicParameters();
                dynamicParameters.Add("@NormalizedUserName", normalizedUserName);
                return await sqlConnection.QueryFirstOrDefaultAsync<User>("ps_AspNetUsers_s_byNormalizedName",
                    dynamicParameters, commandType: CommandType.StoredProcedure).ConfigureAwait(false);
            }
        }

        /// <inheritdoc />
        public Task<string> GetNormalizedUserNameAsync(User user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.NormalizedUserName);
        }

        /// <inheritdoc />
        public Task<string> GetUserIdAsync(User user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.Id.ToString());
        }

        /// <inheritdoc />
        public Task<string> GetUserNameAsync(User user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.UserName);
        }

        /// <inheritdoc />
        public Task SetNormalizedUserNameAsync(User user, string normalizedName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.NormalizedUserName = normalizedName;
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public Task SetUserNameAsync(User user, string userName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.UserName = userName;
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public async Task<IdentityResult> UpdateAsync(User user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            using (SqlConnection sqlConnection = new SqlConnection(_connectionString))
            {
                await sqlConnection.OpenAsync().ConfigureAwait(false);
                DynamicParameters dynamicParameters = user.ToDynamicParameters();
                dynamicParameters.Add("@Id", user.Id);
                await sqlConnection.ExecuteAsync(Constants.PS_AspNetUsers_Update, dynamicParameters, commandType: CommandType.StoredProcedure).ConfigureAwait(false);
                return IdentityResult.Success;
            }
        }
    }
}
