using Dapper;
using Identity.Domain;
using Identity.Domain.Model;
using Identity.Infrastructure.Assemblers;
using Identity.Infrastructure.Resources;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using System;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Identity.Infrastructure.Repositories
{
    /// <summary>
    /// Roles repository class
    /// </summary>
    public class RolesRepository : IRoleStore<Role>, IQueryableRoleStore<Role>
    {
        /// <summary>
        /// identity database connection string
        /// </summary>
        private readonly string _connectionString;

        /// <summary>
        /// Initializes a new instance of the <see cref="RolesRepository"/> class
        /// </summary>
        /// <param name="configuration">configuration object</param>
        public RolesRepository(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("IdentityConnection");
        }

        /// <summary>
        /// Dispose managed and unmanaged resources
        /// </summary>
        public void Dispose()
        {
            // TODO
        }

        /// <inheritdoc />
        public async Task<IdentityResult> CreateAsync(Role role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (SqlConnection sqlConnection = new SqlConnection(_connectionString))
            {
                await sqlConnection.OpenAsync().ConfigureAwait(false);
                role.Id = await sqlConnection.ExecuteScalarAsync<int>(Constants.PS_AspNetRoles_Insert, 
                    role.ToDynamicParameters(), commandType: CommandType.StoredProcedure).ConfigureAwait(false);
                return IdentityResult.Success;
            }
        }

        /// <inheritdoc />
        public async Task<IdentityResult> DeleteAsync(Role role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (SqlConnection sqlConnection = new SqlConnection(_connectionString))
            {
                await sqlConnection.OpenAsync().ConfigureAwait(false);
                DynamicParameters dynamicParameters = new DynamicParameters();
                dynamicParameters.Add("@Id", role.Id);
                await sqlConnection.ExecuteAsync(Constants.PS_AspNetRoles_Delete, dynamicParameters, commandType: CommandType.StoredProcedure).ConfigureAwait(false);
                return IdentityResult.Success;
            }
        }

        /// <inheritdoc />
        public async Task<Role> FindByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!int.TryParse(roleId, out int parsedUserId))
            {
                throw new FormatException(string.Format(MessageResources.ValueNotInteger, nameof(roleId)));
            }

            using (SqlConnection sqlConnection = new SqlConnection(_connectionString))
            {
                await sqlConnection.OpenAsync().ConfigureAwait(false);
                DynamicParameters dynamicParameters = new DynamicParameters();
                dynamicParameters.Add("@Id", parsedUserId);
                return await sqlConnection.QueryFirstOrDefaultAsync<Role>(Constants.PS_AspNetRoles_SelectById, 
                    dynamicParameters, commandType: CommandType.StoredProcedure).ConfigureAwait(false);
            }
        }

        /// <inheritdoc />
        public async Task<Role> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (SqlConnection sqlConnection = new SqlConnection(_connectionString))
            {
                await sqlConnection.OpenAsync().ConfigureAwait(false);
                DynamicParameters dynamicParameters = new DynamicParameters();
                dynamicParameters.Add("@NormalizedName", normalizedRoleName);
                return await sqlConnection.QueryFirstOrDefaultAsync<Role>(Constants.PS_AspNetRoles_SelectByNormalizedName,
                    dynamicParameters, commandType: CommandType.StoredProcedure).ConfigureAwait(false);
            }
        }

        /// <inheritdoc />
        public Task<string> GetNormalizedRoleNameAsync(Role role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            return Task.FromResult(role.NormalizedName);
        }

        /// <inheritdoc />
        public Task<string> GetRoleIdAsync(Role role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            return Task.FromResult(role.Id.ToString());
        }

        /// <inheritdoc />
        public Task<string> GetRoleNameAsync(Role role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            return Task.FromResult(role.Name);
        }

        /// <inheritdoc />
        public Task SetNormalizedRoleNameAsync(Role role, string normalizedName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            role.NormalizedName = normalizedName;
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public Task SetRoleNameAsync(Role role, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            role.Name = roleName;
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public async Task<IdentityResult> UpdateAsync(Role role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            using (SqlConnection sqlConnection = new SqlConnection(_connectionString))
            {
                await sqlConnection.OpenAsync().ConfigureAwait(false);
                DynamicParameters dynamicParameters = role.ToDynamicParameters();
                dynamicParameters.Add("@Id", role.Id);
                await sqlConnection.ExecuteAsync(Constants.PS_AspNetRoles_Update, dynamicParameters, commandType: CommandType.StoredProcedure).ConfigureAwait(false);
                return IdentityResult.Success;
            }
        }

        /// <inheritdoc />
        public IQueryable<Role> Roles
        {
            get
            {
                using (SqlConnection sqlConnection = new SqlConnection(_connectionString))
                {
                    sqlConnection.Open();
                    return sqlConnection.Query<Role>(Constants.PS_AspNetRoles_SelectAll, null, commandType: CommandType.StoredProcedure).AsQueryable();
                }
            }
        }
    }
}
