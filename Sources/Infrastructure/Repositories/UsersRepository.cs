using Dapper;
using Identity.Domain;
using Identity.Domain.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.Linq;

namespace Identity.Infrastructure.Repositories
{
    /// <summary>
    /// Users repository class
    /// </summary>
    public partial class UsersRepository : IQueryableUserStore<User>
    {
        /// <summary>
        /// identity database connection string
        /// </summary>
        private readonly string _connectionString;

        /// <summary>
        /// instantiate a new instance of the <see cref="UsersRepository"/> class
        /// </summary>
        /// <param name="configuration">configuration object</param>
        public UsersRepository(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("IdentityConnection");
        }

        /// <inheritdoc />
        public IQueryable<User> Users
        {
            get
            {
                using (SqlConnection sqlConnection = new SqlConnection(_connectionString))
                {
                    sqlConnection.Open();
                    return sqlConnection.Query<User>(Constants.PS_AspNetUsers_SelectAll, null, commandType: CommandType.StoredProcedure).AsQueryable();
                }
            }
        }

        /// <summary>
        /// dipose managed and unmanaged resources
        /// </summary>
        public void Dispose()
        {
            // TODO
        }
    }
}
