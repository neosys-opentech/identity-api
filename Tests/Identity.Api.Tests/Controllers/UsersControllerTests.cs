using Identity.Api.Controllers;
using Identity.Api.Resources;
using Identity.Domain.Requests;
using Identity.Domain.Results;
using Identity.Infrastructure.Services;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace Identity.Api.Tests.Controllers
{
    /// <summary>
    /// unit tests class for <see cref="UsersController"/>
    /// </summary>
    public class UsersControllerTests
    {
        /// <summary>
        /// users controller
        /// </summary>
        private readonly UsersController _usersController;

        /// <summary>
        /// identity service mock
        /// </summary>
        private readonly Mock<IIdentityService> _identityServiceMock;

        /// <summary>
        /// Initializes a new instance of the <see cref="UsersController"/>
        /// </summary>
        public UsersControllerTests()
        {
            _identityServiceMock = new Mock<IIdentityService>();
            _usersController = new UsersController(_identityServiceMock.Object);
        }

        /// <summary>
        /// Given null request
        /// When authenticating user
        /// Return bad request
        /// </summary>
        [Fact]
        public async Task AuthenticateUserAsync_NullRequest_ReturnBadRequest()
        {
            // Arrange
            AuthenticationRequest request = null;

            // Act
            BadRequestObjectResult result = await _usersController.AuthenticateUserAsync(request).ConfigureAwait(false)
                as BadRequestObjectResult;

            // Assert
            Assert.NotNull(result);
            AuthenticationResult authenticationResult = result.Value as AuthenticationResult;
            Assert.False(authenticationResult.OperationStatus);
            Assert.Equal(MessageResources.AuthRequestEmpty, authenticationResult.ErrorMessages.First());
        }

        /// <summary>
        /// Given not null request
        /// and identity service throws exception
        /// When authenticating user
        /// Return server error
        /// </summary>
        [Fact]
        public async Task AuthenticateUserAsync_NotNullRequest_IdentityServiceThrowsException_ReturnServerError()
        {
            // Arrange
            AuthenticationRequest request = new AuthenticationRequest
            {
                Login = "niahahaw",
                Password = "mydummypassword"
            };
            _identityServiceMock.Setup(mock => mock.AuthenticateUserAsync(request)).ThrowsAsync(new Exception());

            // Act
            ObjectResult result = await _usersController.AuthenticateUserAsync(request).ConfigureAwait(false)
                as ObjectResult;

            // Assert
            Assert.NotNull(result);
            Assert.Equal(500, result.StatusCode);
            AuthenticationResult authenticationResult = result.Value as AuthenticationResult;
            Assert.False(authenticationResult.OperationStatus);
            Assert.Equal(MessageResources.AuthImpossible, 
                authenticationResult.ErrorMessages.First());
        }

        /// <summary>
        /// Given not null request
        /// and identity service returns a response
        /// When authenticating user
        /// Return ok result
        /// </summary>
        [Fact]
        public async Task AuthenticateUserAsync_NotNullRequest_IdentityServiceReturnsResponse_ReturnOkResult()
        {
            // Arrange
            string token = "haw-haw no token";
            AuthenticationRequest request = new AuthenticationRequest
            {
                Login = "niahahaw",
                Password = "mydummypassword"
            };
            _identityServiceMock.Setup(mock => mock.AuthenticateUserAsync(request)).ReturnsAsync(new AuthenticationResult
            {
                OperationStatus = true,
                Token = token
            });

            
            // Act
            OkObjectResult result = await _usersController.AuthenticateUserAsync(request).ConfigureAwait(false)
                as OkObjectResult;

            // Assert
            Assert.NotNull(result);;
            AuthenticationResult authenticationResult = result.Value as AuthenticationResult;
            Assert.True(authenticationResult.OperationStatus);
            Assert.Equal(token, authenticationResult.Token);
        }

        /// <summary>
        /// Given null request
        /// When creating user
        /// Return bad request
        /// </summary>
        [Fact]
        public async Task CreateUserAsync_NullRequest_ReturnBadRequest()
        {
            // Arrange
            UserCreationRequest request = null;

            // Act
            BadRequestObjectResult result = await _usersController.CreateUserAsync(request).ConfigureAwait(false)
                as BadRequestObjectResult;

            // Assert
            Assert.NotNull(result);
            ResultMessage objectResult = result.Value as ResultMessage;
            Assert.False(objectResult.OperationStatus);
            Assert.Equal(MessageResources.UserCreationRequestEmpty, objectResult.ErrorMessages.First());
        }

        /// <summary>
        /// Given not null request
        /// and identity service throws exception
        /// When creating user
        /// Return server error
        /// </summary>
        [Fact]
        public async Task CreateUserAsync_NotNullRequest_IdentityServiceThrowsException_ReturnServerError()
        {
            // Arrange
            UserCreationRequest request = new UserCreationRequest
            {
                Login = "niahahaw",
                Password = "mydummypassword",
                Email = "pig@gmail.com"
            };
            _identityServiceMock.Setup(mock => mock.CreateUserAsync(request)).ThrowsAsync(new Exception());

            // Act
            ObjectResult result = await _usersController.CreateUserAsync(request).ConfigureAwait(false)
                as ObjectResult;

            // Assert
            Assert.NotNull(result);
            Assert.Equal(500, result.StatusCode);
            ResultMessage resultObject = result.Value as ResultMessage;
            Assert.False(resultObject.OperationStatus);
            Assert.Equal(MessageResources.UserCreationFailed,
                resultObject.ErrorMessages.First());
        }

        /// <summary>
        /// Given not null request
        /// and identity service returns a response
        /// When creating user
        /// Return ok result
        /// </summary>
        [Fact]
        public async Task CreateUserAsync_NotNullRequest_IdentityServiceReturnsResponse_ReturnOkResult()
        {
            // Arrange
            UserCreationRequest request = new UserCreationRequest
            {
                Login = "niahahaw",
                Password = "mydummypassword",
                Email = "nia@gmail.com"
            };
            _identityServiceMock.Setup(mock => mock.CreateUserAsync(request)).ReturnsAsync(new ResultMessage
            {
                OperationStatus = true
            });


            // Act
            OkObjectResult result = await _usersController.CreateUserAsync(request).ConfigureAwait(false)
                as OkObjectResult;

            // Assert
            Assert.NotNull(result); ;
            ResultMessage authenticationResult = result.Value as ResultMessage;
            Assert.True(authenticationResult.OperationStatus);
        }

        /// <summary>
        /// Given null request
        /// When deleting user
        /// Return bad request
        /// </summary>
        [Fact]
        public async Task DeleteUserAsync_NullRequest_ReturnBadRequest()
        {
            // Arrange
            DeleteUserRequest request = null;

            // Act
            BadRequestObjectResult result = await _usersController.DeleteUserAsync(request).ConfigureAwait(false)
                as BadRequestObjectResult;

            // Assert
            Assert.NotNull(result);
            ResultMessage objectResult = result.Value as ResultMessage;
            Assert.False(objectResult.OperationStatus);
            Assert.Equal(MessageResources.UserDeletionRequestEmpty, objectResult.ErrorMessages.First());
        }

        /// <summary>
        /// Given not null request
        /// and identity service throws exception
        /// When deleting user
        /// Return server error
        /// </summary>
        [Fact]
        public async Task DeleteUserAsync_NotNullRequest_IdentityServiceThrowsException_ReturnServerError()
        {
            // Arrange
            DeleteUserRequest request = new DeleteUserRequest
            {
                Login = "niahahaw"
            };
            _identityServiceMock.Setup(mock => mock.DeleteUserAsync(request)).ThrowsAsync(new Exception());

            // Act
            ObjectResult result = await _usersController.DeleteUserAsync(request).ConfigureAwait(false)
                as ObjectResult;

            // Assert
            Assert.NotNull(result);
            Assert.Equal(500, result.StatusCode);
            ResultMessage resultObject = result.Value as ResultMessage;
            Assert.False(resultObject.OperationStatus);
            Assert.Equal(MessageResources.UserDeletionFailed,
                resultObject.ErrorMessages.First());
        }

        /// <summary>
        /// Given not null request
        /// and identity service returns a response
        /// When deleting user
        /// Return ok result
        /// </summary>
        [Fact]
        public async Task DeleteUserAsync_NotNullRequest_IdentityServiceReturnsResponse_ReturnOkResult()
        {
            // Arrange
            DeleteUserRequest request = new DeleteUserRequest
            {
                Login = "niahahaw"
            };
            _identityServiceMock.Setup(mock => mock.DeleteUserAsync(request)).ReturnsAsync(new ResultMessage
            {
                OperationStatus = true
            });


            // Act
            OkObjectResult result = await _usersController.DeleteUserAsync(request).ConfigureAwait(false)
                as OkObjectResult;

            // Assert
            Assert.NotNull(result); ;
            ResultMessage authenticationResult = result.Value as ResultMessage;
            Assert.True(authenticationResult.OperationStatus);
        }

        /// <summary>
        /// Given null request
        /// When assigning role to user
        /// Return bad request
        /// </summary>
        [Fact]
        public async Task AssignRoleToUserAsync_NullRequest_ReturnBadRequest()
        {
            // Arrange
            UserRoleAssignmentRequest request = null;

            // Act
            BadRequestObjectResult result = await _usersController.AssignRoleToUserAsync(request).ConfigureAwait(false)
                as BadRequestObjectResult;

            // Assert
            Assert.NotNull(result);
            ResultMessage objectResult = result.Value as ResultMessage;
            Assert.False(objectResult.OperationStatus);
            Assert.Equal(MessageResources.RoleAssignmentRequestEmpty, objectResult.ErrorMessages.First());
        }

        /// <summary>
        /// Given not null request
        /// and identity service throws exception
        /// When assigning role to user
        /// Return server error
        /// </summary>
        [Fact]
        public async Task AssignRoleToUserAsync_NotNullRequest_IdentityServiceThrowsException_ReturnServerError()
        {
            // Arrange
            UserRoleAssignmentRequest request = new UserRoleAssignmentRequest
            {
                Login = "niahahaw",
                RoleName = "bully"
            };
            _identityServiceMock.Setup(mock => mock.AssignRoleToUserAsync(request)).ThrowsAsync(new Exception());

            // Act
            ObjectResult result = await _usersController.AssignRoleToUserAsync(request).ConfigureAwait(false)
                as ObjectResult;

            // Assert
            Assert.NotNull(result);
            Assert.Equal(500, result.StatusCode);
            ResultMessage resultObject = result.Value as ResultMessage;
            Assert.False(resultObject.OperationStatus);
            Assert.Equal(MessageResources.RoleAssignmentFailed,
                resultObject.ErrorMessages.First());
        }

        /// <summary>
        /// Given not null request
        /// and identity service returns a response
        /// When assigning role to user
        /// Return ok result
        /// </summary>
        [Fact]
        public async Task AssignRoleToUserAsync_NotNullRequest_IdentityServiceReturnsResponse_ReturnOkResult()
        {
            // Arrange
            UserRoleAssignmentRequest request = new UserRoleAssignmentRequest
            {
                Login = "niahahaw",
                RoleName = "bully"
            };
            _identityServiceMock.Setup(mock => mock.AssignRoleToUserAsync(request)).ReturnsAsync(new ResultMessage
            {
                OperationStatus = true
            });


            // Act
            OkObjectResult result = await _usersController.AssignRoleToUserAsync(request).ConfigureAwait(false)
                as OkObjectResult;

            // Assert
            Assert.NotNull(result); ;
            ResultMessage authenticationResult = result.Value as ResultMessage;
            Assert.True(authenticationResult.OperationStatus);
        }

        /// <summary>
        /// Given null request
        /// When unassigning user from a role
        /// Return bad request
        /// </summary>
        [Fact]
        public async Task UnassignRoleToUserAsync_NullRequest_ReturnBadRequest()
        {
            // Arrange
            UserRoleAssignmentRequest request = null;

            // Act
            BadRequestObjectResult result = await _usersController.UnassignRoleToUserAsync(request).ConfigureAwait(false)
                as BadRequestObjectResult;

            // Assert
            Assert.NotNull(result);
            ResultMessage objectResult = result.Value as ResultMessage;
            Assert.False(objectResult.OperationStatus);
            Assert.Equal(MessageResources.RoleUnassignmentRequestEmpty, objectResult.ErrorMessages.First());
        }

        /// <summary>
        /// Given not null request
        /// and identity service throws exception
        /// When unassigning user from a role
        /// Return server error
        /// </summary>
        [Fact]
        public async Task UnassignRoleToUserAsync_NotNullRequest_IdentityServiceThrowsException_ReturnServerError()
        {
            // Arrange
            UserRoleAssignmentRequest request = new UserRoleAssignmentRequest
            {
                Login = "niahahaw",
                RoleName = "bully"
            };
            _identityServiceMock.Setup(mock => mock.UnassignRoleToUserAsync(request)).ThrowsAsync(new Exception());

            // Act
            ObjectResult result = await _usersController.UnassignRoleToUserAsync(request).ConfigureAwait(false)
                as ObjectResult;

            // Assert
            Assert.NotNull(result);
            Assert.Equal(500, result.StatusCode);
            ResultMessage resultObject = result.Value as ResultMessage;
            Assert.False(resultObject.OperationStatus);
            Assert.Equal(MessageResources.RoleUnassignmentRequestFailed,
                resultObject.ErrorMessages.First());
        }

        /// <summary>
        /// Given not null request
        /// and identity service returns a response
        /// When unassigning user from a role
        /// Return ok result
        /// </summary>
        [Fact]
        public async Task UnassignRoleToUserAsync_NotNullRequest_IdentityServiceReturnsResponse_ReturnOkResult()
        {
            // Arrange
            UserRoleAssignmentRequest request = new UserRoleAssignmentRequest
            {
                Login = "niahahaw",
                RoleName = "bully"
            };
            _identityServiceMock.Setup(mock => mock.UnassignRoleToUserAsync(request)).ReturnsAsync(new ResultMessage
            {
                OperationStatus = true
            });


            // Act
            OkObjectResult result = await _usersController.UnassignRoleToUserAsync(request).ConfigureAwait(false)
                as OkObjectResult;

            // Assert
            Assert.NotNull(result); ;
            ResultMessage authenticationResult = result.Value as ResultMessage;
            Assert.True(authenticationResult.OperationStatus);
        }

        /// <summary>
        /// Given null request
        /// When initializing user password
        /// Return bad request
        /// </summary>
        [Fact]
        public async Task InitializeUserPasswordAsync_NullRequest_ReturnBadRequest()
        {
            // Arrange
            PasswordInitializationRequest request = null;

            // Act
            BadRequestObjectResult result = await _usersController.InitializeUserPasswordAsync(request).ConfigureAwait(false)
                as BadRequestObjectResult;

            // Assert
            Assert.NotNull(result);
            ResultMessage objectResult = result.Value as ResultMessage;
            Assert.False(objectResult.OperationStatus);
            Assert.Equal(MessageResources.PasswordReinitRequestEmpty, objectResult.ErrorMessages.First());
        }

        /// <summary>
        /// Given not null request
        /// and identity service throws exception
        /// When initializing user password
        /// Return server error
        /// </summary>
        [Fact]
        public async Task InitializeUserPasswordAsync_NotNullRequest_IdentityServiceThrowsException_ReturnServerError()
        {
            // Arrange
            PasswordInitializationRequest request = new PasswordInitializationRequest
            {
                Login = "elbarto",
                NewPassword = "skiner wienner",
                OldPassword = "skinner the old wienner"
            };
            _identityServiceMock.Setup(mock => mock.InitializeUserPasswordAsync(request)).ThrowsAsync(new Exception());

            // Act
            ObjectResult result = await _usersController.InitializeUserPasswordAsync(request).ConfigureAwait(false)
                as ObjectResult;

            // Assert
            Assert.NotNull(result);
            Assert.Equal(500, result.StatusCode);
            ResultMessage resultObject = result.Value as ResultMessage;
            Assert.False(resultObject.OperationStatus);
            Assert.Equal(MessageResources.PasswordReinitFailed, resultObject.ErrorMessages.First());
        }

        /// <summary>
        /// Given not null request
        /// and identity service returns a response
        /// When initializing user password
        /// Return ok result
        /// </summary>
        [Fact]
        public async Task InitializeUserPasswordAsync_NotNullRequest_IdentityServiceReturnsResponse_ReturnOkResult()
        {
            // Arrange
            PasswordInitializationRequest request = new PasswordInitializationRequest
            {
                Login = "elbarto",
                NewPassword = "skiner wienner",
                OldPassword = "skinner the old wienner"
            };
            _identityServiceMock.Setup(mock => mock.InitializeUserPasswordAsync(request)).ReturnsAsync(new ResultMessage
            {
                OperationStatus = true
            });


            // Act
            OkObjectResult result = await _usersController.InitializeUserPasswordAsync(request).ConfigureAwait(false)
                as OkObjectResult;

            // Assert
            Assert.NotNull(result); ;
            ResultMessage authenticationResult = result.Value as ResultMessage;
            Assert.True(authenticationResult.OperationStatus);
        }

        /// <summary>
        /// Given null request
        /// When updating user password
        /// Return bad request
        /// </summary>
        [Fact]
        public async Task UpdateUserPasswordAsync_NullRequest_ReturnBadRequest()
        {
            // Arrange
            PasswordInitializationRequest request = null;

            // Act
            BadRequestObjectResult result = await _usersController.UpdateUserPasswordAsync(request).ConfigureAwait(false)
                as BadRequestObjectResult;

            // Assert
            Assert.NotNull(result);
            ResultMessage objectResult = result.Value as ResultMessage;
            Assert.False(objectResult.OperationStatus);
            Assert.Equal(MessageResources.PasswordUpdateRequestEmpty, objectResult.ErrorMessages.First());
        }

        /// <summary>
        /// Given not null request
        /// and identity service throws exception
        /// When updating user password
        /// Return server error
        /// </summary>
        [Fact]
        public async Task UpdateUserPasswordAsync_NotNullRequest_IdentityServiceThrowsException_ReturnServerError()
        {
            // Arrange
            PasswordInitializationRequest request = new PasswordInitializationRequest
            {
                Login = "elbarto",
                NewPassword = "skiner wienner",
                OldPassword = "skinner the old wienner"
            };
            _identityServiceMock.Setup(mock => mock.UpdateUserPasswordAsync(request)).ThrowsAsync(new Exception());

            // Act
            ObjectResult result = await _usersController.UpdateUserPasswordAsync(request).ConfigureAwait(false)
                as ObjectResult;

            // Assert
            Assert.NotNull(result);
            Assert.Equal(500, result.StatusCode);
            ResultMessage resultObject = result.Value as ResultMessage;
            Assert.False(resultObject.OperationStatus);
            Assert.Equal(MessageResources.PasswordUpdateFailed, resultObject.ErrorMessages.First());
        }

        /// <summary>
        /// Given not null request
        /// and identity service returns a response
        /// When updating user password
        /// Return ok result
        /// </summary>
        [Fact]
        public async Task UpdateUserPasswordAsync_NotNullRequest_IdentityServiceReturnsResponse_ReturnOkResult()
        {
            // Arrange
            PasswordInitializationRequest request = new PasswordInitializationRequest
            {
                Login = "elbarto",
                NewPassword = "skiner wienner",
                OldPassword = "skinner the old wienner"
            };
            _identityServiceMock.Setup(mock => mock.UpdateUserPasswordAsync(request)).ReturnsAsync(new ResultMessage
            {
                OperationStatus = true
            });


            // Act
            OkObjectResult result = await _usersController.UpdateUserPasswordAsync(request).ConfigureAwait(false)
                as OkObjectResult;

            // Assert
            Assert.NotNull(result); ;
            ResultMessage authenticationResult = result.Value as ResultMessage;
            Assert.True(authenticationResult.OperationStatus);
        }

        /// <summary>
        /// Given identity service retrieves users successfully
        /// When getting all users
        /// return user list
        /// </summary>
        [Fact]
        public void GetAllUsers_WhenIdentityServiceSucceeds_ReturnUsersListMessage()
        {
            // Arrange
            UsersListMessage usersListMessage = new UsersListMessage
            {
                OperationStatus = true,
                Users = new List<UserResult>
                {
                    new UserResult
                    {
                        Login = "nihaw",
                        Email = "nihaw@hotmail.com",
                        CreationDate = DateTime.Now,
                        UpdateDate = DateTime.Now
                    }
                }
            };
            _identityServiceMock.Setup(mock => mock.Users).Returns(usersListMessage);

            // Act
            OkObjectResult result = _usersController.GetAllUsers() as OkObjectResult;

            // Assert
            Assert.NotNull(result);
            Assert.Equal(usersListMessage, result.Value);
        }

        /// <summary>
        /// Given identity service faild to retrieve users
        /// When getting all users
        /// return error message
        /// </summary>
        [Fact]
        public void GetAllUsers_WhenIdentityServiceFails_ReturnErrorMessage()
        {
            // Arrange
            _identityServiceMock.Setup(mock => mock.Users).Throws(new Exception());

            // Act
            ObjectResult result = _usersController.GetAllUsers() as ObjectResult;

            // Assert
            Assert.NotNull(result);
            Assert.Equal(500, result.StatusCode);
            UsersListMessage resultValue = result.Value as UsersListMessage;
            Assert.False(resultValue.OperationStatus);
            Assert.Equal(MessageResources.FetchingAllUsersFailed, resultValue.ErrorMessages.First());
        }
    }
}
