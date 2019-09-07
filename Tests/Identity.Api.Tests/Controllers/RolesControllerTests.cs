using Identity.Api.Controllers;
using Identity.Api.Resources;
using Identity.Domain.Results;
using Identity.Infrastructure.Services;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Identity.Api.Tests.Controllers
{
    /// <summary>
    /// Unit tests class for <see cref="RolesController"/>
    /// </summary>
    public class RolesControllerTests
    {
        private readonly Mock<IIdentityService> _identityServiceMock;
        private readonly RolesController _rolesController;

        /// <summary>
        /// Initializes a new instance of the <see cref="RolesControllerTests"/> class
        /// </summary>
        public RolesControllerTests()
        {
            _identityServiceMock = new Mock<IIdentityService>();
            _rolesController = new RolesController(_identityServiceMock.Object);
        }

        /// <summary>
        /// Given identity service retrieves roles successfully
        /// When getting all roles
        /// return role list
        /// </summary>
        [Fact]
        public void GetAllRoles_WhenIdentityServiceSucceeds_ReturnRolesListMessage()
        {
            // Arrange
            RolesListMessage rolesListMessage = new RolesListMessage
            {
                OperationStatus = true,
                Roles = new List<RoleResult>
                {
                    new RoleResult
                    {
                        Name = "nihaw",
                        CreationDate = DateTime.Now,
                        UpdateDate = DateTime.Now
                    }
                }
            };
            _identityServiceMock.Setup(mock => mock.Roles).Returns(rolesListMessage);

            // Act
            OkObjectResult result = _rolesController.GetAllRoles() as OkObjectResult;

            // Assert
            Assert.NotNull(result);
            Assert.Equal(rolesListMessage, result.Value);
        }

        /// <summary>
        /// Given identity service faild to retrieve roles
        /// When getting all roles
        /// return error message
        /// </summary>
        [Fact]
        public void GetAllRoles_WhenIdentityServiceFails_ReturnErrorMessage()
        {
            // Arrange
            _identityServiceMock.Setup(mock => mock.Roles).Throws(new Exception());

            // Act
            ObjectResult result = _rolesController.GetAllRoles() as ObjectResult;

            // Assert
            Assert.NotNull(result);
            Assert.Equal(500, result.StatusCode);
            RolesListMessage resultValue = result.Value as RolesListMessage;
            Assert.False(resultValue.OperationStatus);
            Assert.Equal(MessageResources.FetchingAllRolesFailed, resultValue.ErrorMessages.First());
        }
    }
}
