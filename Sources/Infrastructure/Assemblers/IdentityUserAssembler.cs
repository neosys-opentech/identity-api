using Dapper;
using Identity.Domain.Model;
using Identity.Domain.Results;
using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;
using System.Linq;

namespace Identity.Infrastructure.Assemblers
{
    /// <summary>
    /// identity user assembler static class
    /// </summary>
    internal static class IdentityUserAssembler
    {
        /// <summary>
        /// assemble from identity user to dynamic parameters
        /// </summary>
        /// <param name="identityUser">identity user object</param>
        /// <returns>dynamic parameters</returns>
        internal static DynamicParameters ToDynamicParameters(this User identityUser)
        {
            if (identityUser == null)
            {
                return null;
            }

            DynamicParameters dynamicParameters = new DynamicParameters();
            dynamicParameters.Add("@UserName", identityUser.UserName);
            dynamicParameters.Add("@NormalizedUserName", identityUser.NormalizedUserName);
            dynamicParameters.Add("@Email", identityUser.Email);
            dynamicParameters.Add("@NormalizedEmail", identityUser.NormalizedEmail);
            dynamicParameters.Add("@EmailConfirmed", identityUser.EmailConfirmed);
            dynamicParameters.Add("@PasswordHash", identityUser.PasswordHash);
            dynamicParameters.Add("@SecurityStamp", identityUser.SecurityStamp);
            dynamicParameters.Add("@ConcurrencyStamp", identityUser.ConcurrencyStamp);
            dynamicParameters.Add("@PhoneNumber", identityUser.PhoneNumber);
            dynamicParameters.Add("@PhoneNumberConfirmed", identityUser.PhoneNumberConfirmed);
            dynamicParameters.Add("@TwoFactorEnabled", identityUser.TwoFactorEnabled);
            dynamicParameters.Add("@LockoutEnd", identityUser.LockoutEnd);
            dynamicParameters.Add("@LockoutEnabled", identityUser.LockoutEnabled);
            dynamicParameters.Add("@AccessFailedCount", identityUser.AccessFailedCount);
            return dynamicParameters;
        }

        /// <summary>
        /// assemble from identity user to result user
        /// </summary>
        /// <param name="user">identity user object</param>
        /// <returns>result user</returns>
        internal static UserResult ToResult(this User user)
        {
            if (user == null)
            {
                return null;
            }

            return new UserResult
            {
                Email = user.Email,
                Login = user.UserName,
                CreationDate = user.CreationDate,
                UpdateDate = user.UpdateDate
            };
        }

        /// <summary>
        /// assemble from identity user list to result user list
        /// </summary>
        /// <param name="userList">identity user list</param>
        /// <returns>Result user list</returns>
        internal static IEnumerable<UserResult> ToResultList(this IEnumerable<User> userList)
        {
            if (userList == null || !userList.Any())
            {
                return null;
            }

            return userList.Where(u => u != null).Select(u => u.ToResult());
        }
    }
}
