using Identity.Domain.Configurations;
using Identity.Domain.Model;
using Identity.Domain.Requests;
using Identity.Domain.Results;
using Identity.Infrastructure.Assemblers;
using Identity.Infrastructure.Resources;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Identity.Infrastructure.Services
{
    /// <summary>
    /// identity service implementation
    /// </summary>
    public class IdentityService : IIdentityService
    {
        private readonly SignInManager<User> _signInManager;
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<Role> _roleManager;
        private readonly IdentityConfiguration _configuration;

        /// <summary>
        /// Initializes a new instance of the <see cref="IdentityService"/> class
        /// </summary>
        /// <param name="signInManager">identity sign in manager</param>
        /// <param name="userManager">identity user manager</param>
        /// <param name="configuration">identity service configuration object</param>
        /// <param name="roleManager">identity role manager</param>
        public IdentityService(SignInManager<User> signInManager,
            UserManager<User> userManager,
            IOptions<IdentityConfiguration> configuration,
            RoleManager<Role> roleManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration.Value;
        }

        /// <inheritdoc />
        public async Task<AuthenticationResult> AuthenticateUserAsync(AuthenticationRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            User identityUser = await _userManager.FindByNameAsync(request.Login).ConfigureAwait(false);
            SignInResult signInresult = await _signInManager.CheckPasswordSignInAsync(identityUser, request.Password, false)
                .ConfigureAwait(false);

            List<string> errorList = new List<string>();
            AuthenticationResult authenticationResult = new AuthenticationResult
            {
                OperationStatus = signInresult.Succeeded,
                ErrorMessages = errorList
            };

            if (!signInresult.Succeeded)
            {
                errorList.Add(MessageResources.WrongCredentials);
                return authenticationResult;
            }

            IList<string> identityUserRoles = await _userManager.GetRolesAsync(identityUser).ConfigureAwait(false);
            authenticationResult.Token = GenerateAuthentificationToken(request.Login, identityUserRoles);
            return authenticationResult;
        }

        /// <inheritdoc />
        public async Task<ResultMessage> CreateUserAsync(UserCreationRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            User newUser = new User
            {
                Email = request.Email,
                UserName = request.Login,
            };

            IdentityResult result = await _userManager.CreateAsync(newUser, request.Password).ConfigureAwait(false);

            return new ResultMessage
            {
                OperationStatus = result.Succeeded,
                ErrorMessages = result.Errors?.Select(err => err.Description)
            };
        }

        /// <inheritdoc />
        public async Task<ResultMessage> DeleteUserAsync(DeleteUserRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            User identityUser = await _userManager.FindByNameAsync(request.Login).ConfigureAwait(false);
            IList<string> identityUserRoles = await _userManager.GetRolesAsync(identityUser).ConfigureAwait(false);

            if (identityUserRoles.Contains("ADMINISTRATOR"))
            {
                return new ResultMessage
                {
                    OperationStatus = false,
                    ErrorMessages = new List<string>
                    { MessageResources.DeleteAdministrator }
                };
            }

            IdentityResult result = await _userManager.DeleteAsync(identityUser).ConfigureAwait(false);

            return new ResultMessage
            {
                OperationStatus = result.Succeeded,
                ErrorMessages = result.Errors?.Select(err => err.Description)
            };
        }

        /// <inheritdoc />
        public async Task<ResultMessage> AssignRoleToUserAsync(UserRoleAssignmentRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            User identityUser = await _userManager.FindByNameAsync(request.Login).ConfigureAwait(false);
            IdentityResult result = await _userManager.AddToRoleAsync(identityUser, request.RoleName).ConfigureAwait(false);

            return new ResultMessage
            {
                OperationStatus = result.Succeeded,
                ErrorMessages = result.Errors?.Select(err => err.Description)
            };
        }

        /// <inheritdoc />
        public async Task<ResultMessage> UnassignRoleToUserAsync(UserRoleAssignmentRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (request.RoleName == "ADMINISTRATOR")
            {
                return new ResultMessage
                {
                    OperationStatus = false,
                    ErrorMessages = new List<string>
                    { MessageResources.UnassignAdminRole }
                };
            }

            User identityUser = await _userManager.FindByNameAsync(request.Login).ConfigureAwait(false);
            IdentityResult result = await _userManager.RemoveFromRoleAsync(identityUser, request.RoleName).ConfigureAwait(false);

            return new ResultMessage
            {
                OperationStatus = result.Succeeded,
                ErrorMessages = result.Errors?.Select(err => err.Description)
            };
        }

        /// <inheritdoc />
        public async Task<ResultMessage> InitializeUserPasswordAsync(PasswordInitializationRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            User identityUser = await _userManager.FindByNameAsync(request.Login).ConfigureAwait(false);
            IList<string> identityUserRoles = await _userManager.GetRolesAsync(identityUser).ConfigureAwait(false);

            if (identityUserRoles.Contains("ADMINISTRATOR"))
            {
                return new ResultMessage
                {
                    OperationStatus = false,
                    ErrorMessages = new List<string>
                    { MessageResources.ReinitializeAdminPassword }
                };
            }

            IdentityResult removePasswordResult = await _userManager.RemovePasswordAsync(identityUser).ConfigureAwait(false);

            if (!removePasswordResult.Succeeded)
            {
                return new ResultMessage
                {
                    OperationStatus = removePasswordResult.Succeeded,
                    ErrorMessages = removePasswordResult.Errors?.Select(err => err.Description)
                };
            }

            IdentityResult newPasswordResult = await _userManager.AddPasswordAsync(identityUser, request.NewPassword).ConfigureAwait(false);

            return new ResultMessage
            {
                OperationStatus = newPasswordResult.Succeeded,
                ErrorMessages = newPasswordResult.Errors?.Select(err => err.Description)
            };
        }

        /// <inheritdoc />
        public async Task<ResultMessage> UpdateUserPasswordAsync(PasswordInitializationRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            User identityUser = await _userManager.FindByNameAsync(request.Login).ConfigureAwait(false);
            IdentityResult changePasswordResult = await _userManager.ChangePasswordAsync(identityUser, request.OldPassword,
                request.NewPassword).ConfigureAwait(false);

            return new ResultMessage
            {
                OperationStatus = changePasswordResult.Succeeded,
                ErrorMessages = changePasswordResult.Errors?.Select(err => err.Description)
            };
        }

        /// <inheritdoc />
        public UsersListMessage Users => new UsersListMessage
        {
            Users = _userManager.Users.ToResultList(),
            OperationStatus = true
        };

        /// <inheritdoc />
        public RolesListMessage Roles => new RolesListMessage
        {
            Roles = _roleManager.Roles.ToResultList(),
            OperationStatus = true
        };

        /// <summary>
        /// generates authentification token
        /// </summary>
        /// <param name="login">user login</param>
        /// <returns>token string</returns>
        private string GenerateAuthentificationToken(string login, IList<string> userRoles)
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            byte[] key = Encoding.UTF8.GetBytes(_configuration.JwtTokenSymmetricKey);
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, login)
            };
            claims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));
            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
