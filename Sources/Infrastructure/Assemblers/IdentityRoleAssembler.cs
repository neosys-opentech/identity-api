using Dapper;
using Identity.Domain.Model;
using Identity.Domain.Results;
using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;
using System.Linq;

namespace Identity.Infrastructure.Assemblers
{
    /// <summary>
    /// identity role assembler static class
    /// </summary>
    internal static class IdentityRoleAssembler
    {
        /// <summary>
        /// assemble from identity role to dynamic parameters
        /// </summary>
        /// <param name="role">identity role object</param>
        /// <returns>dynamic parameters</returns>
        internal static DynamicParameters ToDynamicParameters(this Role role)
        {
            if (role == null)
            {
                return null;
            }

            DynamicParameters dynamicParameters = new DynamicParameters();
            dynamicParameters.Add("@Name", role.Name);
            dynamicParameters.Add("@NormalizedName", role.NormalizedName);
            dynamicParameters.Add("@ConcurrencyStamp", role.ConcurrencyStamp);
            return dynamicParameters;
        }

        /// <summary>
        /// assemble from identity role to role result
        /// </summary>
        /// <param name="role">identity role object</param>
        /// <returns>role result</returns>
        internal static RoleResult ToResult(this Role role)
        {
            if (role == null)
            {
                return null;
            }

            return new RoleResult
            {
                Name = role.Name,
                CreationDate = role.CreationDate,
                UpdateDate = role.UpdateDate
            };
        }

        /// <summary>
        /// assemble from identity role list to result role list
        /// </summary>
        /// <param name="roleList">identity role list</param>
        /// <returns>Result role list</returns>
        internal static IEnumerable<RoleResult> ToResultList(this IEnumerable<Role> roleList)
        {
            if (roleList == null || !roleList.Any())
            {
                return null;
            }

            return roleList.Where(r => r != null).Select(r => r.ToResult());
        }
    }
}
