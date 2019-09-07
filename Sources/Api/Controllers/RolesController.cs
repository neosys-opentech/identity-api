using Identity.Api.Resources;
using Identity.Domain.Results;
using Identity.Infrastructure.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;

namespace Identity.Api.Controllers
{
    /// <summary>
    /// identity role controller
    /// </summary>
    [Route("roles")]
    [ApiController]
    public class RolesController : ControllerBase
    {
        private readonly IIdentityService _identityService;

        /// <summary>
        /// initializes a new instance of <see cref="RolesController"/> class
        /// </summary>
        /// <param name="identityService">identity service</param>
        public RolesController(IIdentityService identityService)
        {
            _identityService = identityService;
        }

        /// <summary>
        /// gets all roles
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "ADMINISTRATOR")]
        public IActionResult GetAllRoles()
        {
            try
            {
                return Ok(_identityService.Roles);
            }
            catch (Exception)
            {
                return StatusCode(500, new RolesListMessage
                {
                    OperationStatus = false,
                    ErrorMessages = new List<string>
                    {
                        MessageResources.FetchingAllRolesFailed
                    }
                });
            }
        }
    }
}