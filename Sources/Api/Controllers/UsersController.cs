using Identity.Api.Resources;
using Identity.Domain.Requests;
using Identity.Domain.Results;
using Identity.Infrastructure.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Identity.Api.Controllers
{
    /// <summary>
    /// identity users controller
    /// </summary>
    [Route("users")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly IIdentityService _identityService;

        /// <summary>
        /// Initializes a new instance of the <see cref="UsersController"/> class
        /// </summary>
        /// <param name="identityService">identity service</param>
        public UsersController(IIdentityService identityService)
        {
            _identityService = identityService;
        }

        /// <summary>
        /// Authenticate user
        /// </summary>
        /// <param name="authenticationRequest">Authentication request</param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("authentication")]
        public async Task<IActionResult> AuthenticateUserAsync(AuthenticationRequest authenticationRequest)
        {
            if (authenticationRequest == null)
            {
                return BadRequest(new AuthenticationResult
                {
                    OperationStatus = false,
                    ErrorMessages = new List<string>
                    {
                        MessageResources.AuthRequestEmpty
                    }
                });
            }

            try
            {
                AuthenticationResult result = await _identityService.AuthenticateUserAsync(authenticationRequest)
                    .ConfigureAwait(false);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new AuthenticationResult
                {
                    OperationStatus = false,
                    ErrorMessages = new List<string>
                    {
                        MessageResources.AuthImpossible
                    }
                });
            }
        }

        /// <summary>
        /// create a new user
        /// </summary>
        /// <param name="authenticationRequest">Authentication request</param>
        /// <returns></returns>
        [HttpPost]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "ADMINISTRATOR")]
        public async Task<IActionResult> CreateUserAsync([FromBody] UserCreationRequest request)
        {
            if (request == null)
            {
                return BadRequest(new ResultMessage
                {
                    OperationStatus = false,
                    ErrorMessages = new List<string> { MessageResources.UserCreationRequestEmpty }
                });
            }

            try
            {
                ResultMessage result = await _identityService.CreateUserAsync(request).ConfigureAwait(false);
                return Ok(result);
            }
            catch (Exception)
            {
                return StatusCode(500, new ResultMessage
                {
                    OperationStatus = false,
                    ErrorMessages = new List<string>
                    {
                        MessageResources.UserCreationFailed
                    }
                });
            }
        }

        /// <summary>
        /// deletes a specific user
        /// </summary>
        /// <param name="request">request object</param>
        /// <returns></returns>
        [HttpDelete]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "ADMINISTRATOR")]
        public async Task<IActionResult> DeleteUserAsync(DeleteUserRequest request)
        {
            if (request == null)
            {
                return BadRequest(new ResultMessage
                {
                    OperationStatus = false,
                    ErrorMessages = new List<string> { MessageResources.UserDeletionRequestEmpty }
                });
            }

            try
            {
                ResultMessage result = await _identityService.DeleteUserAsync(request).ConfigureAwait(false);
                return Ok(result);
            }
            catch (Exception)
            {
                return StatusCode(500, new ResultMessage
                {
                    OperationStatus = false,
                    ErrorMessages = new List<string>
                    {
                        MessageResources.UserDeletionFailed
                    }
                });
            }
        }

        /// <summary>
        /// assigns a role to a specific user
        /// </summary>
        /// <param name="request">user role assignment request</param>
        /// <returns></returns>
        [HttpPost("role")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "ADMINISTRATOR")]
        public async Task<IActionResult> AssignRoleToUserAsync(UserRoleAssignmentRequest request)
        {
            if (request == null)
            {
                return BadRequest(new ResultMessage
                {
                    OperationStatus = false,
                    ErrorMessages = new List<string> { MessageResources.RoleAssignmentRequestEmpty }
                });
            }

            try
            {
                ResultMessage result = await _identityService.AssignRoleToUserAsync(request).ConfigureAwait(false);
                return Ok(result);
            }
            catch (Exception)
            {
                return StatusCode(500, new ResultMessage
                {
                    OperationStatus = false,
                    ErrorMessages = new List<string>
                    {
                        MessageResources.RoleAssignmentFailed
                    }
                });
            }
        }

        /// <summary>
        /// unassigns a users from a specific role
        /// </summary>
        /// <param name="request">user role assignment request</param>
        /// <returns></returns>
        [HttpDelete("role")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "ADMINISTRATOR")]
        public async Task<IActionResult> UnassignRoleToUserAsync(UserRoleAssignmentRequest request)
        {
            if (request == null)
            {
                return BadRequest(new ResultMessage
                {
                    OperationStatus = false,
                    ErrorMessages = new List<string> { MessageResources.RoleUnassignmentRequestEmpty }
                });
            }

            try
            {
                ResultMessage result = await _identityService.UnassignRoleToUserAsync(request).ConfigureAwait(false);
                return Ok(result);
            }
            catch (Exception)
            {
                return StatusCode(500, new ResultMessage
                {
                    OperationStatus = false,
                    ErrorMessages = new List<string>
                    {
                        MessageResources.RoleUnassignmentRequestFailed
                    }
                });
            }
        }

        /// <summary>
        /// initialize a user password
        /// </summary>
        /// <param name="request">password initialization request</param>
        /// <returns></returns>
        [HttpPut("password")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "ADMINISTRATOR")]
        public async Task<IActionResult> InitializeUserPasswordAsync(PasswordInitializationRequest request)
        {
            if (request == null)
            {
                return BadRequest(new ResultMessage
                {
                    OperationStatus = false,
                    ErrorMessages = new List<string> { MessageResources.PasswordReinitRequestEmpty }
                });
            }

            try
            {
                ResultMessage result = await _identityService.InitializeUserPasswordAsync(request).ConfigureAwait(false);
                return Ok(result);
            }
            catch (Exception)
            {
                return StatusCode(500, new ResultMessage
                {
                    OperationStatus = false,
                    ErrorMessages = new List<string>
                    {
                        MessageResources.PasswordReinitFailed
                    }
                });
            }
        }

        /// <summary>
        /// update a user password
        /// </summary>
        /// <param name="request">password initialization request</param>
        /// <returns></returns>
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "ADMINISTRATOR,USER")]
        [HttpPut("own-password")]
        public async Task<IActionResult> UpdateUserPasswordAsync(PasswordInitializationRequest request)
        {
            if (request == null)
            {
                return BadRequest(new ResultMessage
                {
                    OperationStatus = false,
                    ErrorMessages = new List<string> { MessageResources.PasswordUpdateRequestEmpty }
                });
            }

            try
            {
                ResultMessage result = await _identityService.UpdateUserPasswordAsync(request).ConfigureAwait(false);
                return Ok(result);
            }
            catch (Exception)
            {
                return StatusCode(500, new ResultMessage
                {
                    OperationStatus = false,
                    ErrorMessages = new List<string>
                    {
                        MessageResources.PasswordUpdateFailed
                    }
                });
            }
        }

        /// <summary>
        /// gets all users
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "ADMINISTRATOR")]
        public IActionResult GetAllUsers()
        {
            try
            {
                return Ok(_identityService.Users);
            }
            catch (Exception)
            {
                return StatusCode(500, new UsersListMessage
                {
                    OperationStatus = false,
                    ErrorMessages = new List<string>
                    {
                        MessageResources.FetchingAllUsersFailed
                    }
                });
            }
        }
    }
}
