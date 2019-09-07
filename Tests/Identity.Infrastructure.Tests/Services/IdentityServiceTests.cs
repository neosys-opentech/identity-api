using Identity.Domain.Configurations;
using Identity.Domain.Model;
using Identity.Domain.Requests;
using Identity.Domain.Results;
using Identity.Infrastructure.Resources;
using Identity.Infrastructure.Services;
using Identity.Infrastructure.Tests.Resources;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace Identity.Infrastructure.Tests.Services
{
    /// <summary>
    /// unit test class for identity service
    /// </summary>
    public class IdentityServiceTests
    {
        private readonly Mock<SignInManager<User>> _signInManagerMock;
        private readonly Mock<UserManager<User>> _userManagerMock;
        private readonly Mock<RoleManager<Role>> _roleManagerMock;
        private readonly Mock<IOptions<IdentityConfiguration>> _configurationMock;
        private readonly IdentityService _identityService;

        /// <summary>
        /// Initializes a new instance if the <see cref="IdentityServiceTests"/> class
        /// </summary>
        public IdentityServiceTests()
        {
            _userManagerMock = new Mock<UserManager<User>>(new Mock<IUserStore<User>>().Object,
                new Mock<IOptions<IdentityOptions>>().Object, new Mock<IPasswordHasher<User>>().Object,
                new List<IUserValidator<User>>(), new List<IPasswordValidator<User>>(), new Mock<ILookupNormalizer>().Object,
                new IdentityErrorDescriber(), new Mock<IServiceProvider>().Object, new Mock<ILogger<UserManager<User>>>().Object);
            _signInManagerMock = new Mock<SignInManager<User>>(_userManagerMock.Object, new Mock<IHttpContextAccessor>().Object,
                new Mock<IUserClaimsPrincipalFactory<User>>().Object, new Mock<IOptions<IdentityOptions>>().Object,
                new Mock<ILogger<SignInManager<User>>>().Object, new Mock<IAuthenticationSchemeProvider>().Object);
            _roleManagerMock = new Mock<RoleManager<Role>>(new Mock<IRoleStore<Role>>().Object, 
                new List<IRoleValidator<Role>>(), new Mock<ILookupNormalizer>().Object, new IdentityErrorDescriber(),
                new Mock<ILogger<RoleManager<Role>>>().Object);
            _configurationMock = new Mock<IOptions<IdentityConfiguration>>();
            _configurationMock.SetupGet(mock => mock.Value).Returns(new IdentityConfiguration
            {
                JwtTokenSymmetricKey = "sdfhk874QA;:5663"
            });
            _identityService = new IdentityService(_signInManagerMock.Object, _userManagerMock.Object, _configurationMock.Object,
                _roleManagerMock.Object);
        }

        /// <summary>
        /// Given request is null
        /// When authenticating user
        /// Throw <see cref="ArgumentNullException"/> exception
        /// </summary>
        [Fact]
        public async Task AuthenticateUserAsync_GivenNullRequest_ThrowException()
        {
            // Arrange + Act + Assert
            ArgumentNullException exception = await Assert.ThrowsAsync<ArgumentNullException>(() => _identityService.AuthenticateUserAsync(null)).ConfigureAwait(false);
            Assert.Equal(string.Format(ErrorMessages.NullExceptionMessage, "request"), exception.Message);
        }

        /// <summary>
        /// Given valid request
        /// And a successful authentication
        /// When authenticating user
        /// Return success authentification result
        /// </summary>
        [Fact]
        public async Task AuthenticateUserAsync_GivenValidRequestAndSuccessfulAuthentication_ReturnSuccessAuthResult()
        {
            // Arrange
            AuthenticationRequest authentificationRequest = new AuthenticationRequest
            {
                Login = "blablaUser",
                Password = "pif/paf/piao"
            };
            User identityUser = new User
            {
                Id = 1,
                UserName = authentificationRequest.Login
            };
            _userManagerMock.Setup(mock => mock.FindByNameAsync(authentificationRequest.Login)).ReturnsAsync(identityUser);
            _signInManagerMock.Setup(mock => mock.CheckPasswordSignInAsync(It.IsAny<User>(), authentificationRequest.Password, false)).ReturnsAsync(SignInResult.Success);
            _userManagerMock.Setup(mock => mock.GetRolesAsync(identityUser)).ReturnsAsync(new List<string> { "pifUserRole" });

            // Act
            AuthenticationResult result = await _identityService.AuthenticateUserAsync(authentificationRequest).ConfigureAwait(false);

            // Assert
            Assert.NotNull(result);
            Assert.True(result.OperationStatus);
            Assert.True(!string.IsNullOrEmpty(result.Token));
            Assert.Empty(result.ErrorMessages);
        }

        /// <summary>
        /// Given valid request
        /// And a failing authentication
        /// When authenticating user
        /// Return error authentification result
        /// </summary>
        [Fact]
        public async Task AuthenticateUserAsync_GivenValidRequestAndFailingAuthentication_ReturnErrorAuthResult()
        {
            // Arrange
            AuthenticationRequest authentificationRequest = new AuthenticationRequest
            {
                Login = "blablaUser",
                Password = "pif/paf/piao"
            };
            _userManagerMock.Setup(mock => mock.FindByNameAsync(authentificationRequest.Login)).ReturnsAsync(new User
            {
                Id = 1,
                UserName = authentificationRequest.Login
            });
            _signInManagerMock.Setup(mock => mock.CheckPasswordSignInAsync(It.IsAny<User>(), authentificationRequest.Password, false)).ReturnsAsync(SignInResult.Failed);

            // Act
            AuthenticationResult result = await _identityService.AuthenticateUserAsync(authentificationRequest).ConfigureAwait(false);

            // Assert
            Assert.NotNull(result);
            Assert.False(result.OperationStatus);
            Assert.NotEmpty(result.ErrorMessages);
            Assert.Equal(MessageResources.WrongCredentials, result.ErrorMessages.First());
        }

        /// <summary>
        /// Given a request is null
        /// when creating new user
        /// throw <see cref="ArgumentNullException"/> exception
        /// </summary>
        [Fact]
        public async Task CreateUserAsync_GivenRequestIsNull_ThrowArgumentNullException()
        {
            // Arrange
            UserCreationRequest request = null;

            // Act + Assert
            ArgumentNullException exception = 
                await Assert.ThrowsAsync<ArgumentNullException>(() => _identityService.CreateUserAsync(request))
                .ConfigureAwait(false);
            Assert.NotNull(exception);
            Assert.Equal(string.Format(ErrorMessages.NullExceptionMessage, "request"), exception.Message);
        }

        /// <summary>
        /// Given a not null request
        /// And creation is done succcessfully
        /// when creating new user
        /// return success result message
        /// </summary>
        [Fact]
        public async Task CreateUserAsync_GivenNotNullRequest_SuccessfulCreation_ReturnSuccessMessage()
        {
            // Arrange
            UserCreationRequest request = new UserCreationRequest
            {
                Email = "nana@hotmail.com",
                Login = "nani",
                Password = "screwyouPass"
            };
            _userManagerMock.Setup(mock => mock.CreateAsync(It.Is<User>(user => user.Email == request.Email
                && user.UserName == request.Login), request.Password)).ReturnsAsync(IdentityResult.Success);

            // Act
            ResultMessage result = await _identityService.CreateUserAsync(request).ConfigureAwait(false);

            // Assert
            Assert.NotNull(result);
            Assert.True(result.OperationStatus);
        }

        /// <summary>
        /// Given a not null request
        /// and creation failed
        /// when creating new user
        /// return failing result message
        /// </summary>
        [Fact]
        public async Task CreateUserAsync_GivenNotNullRequest_CreationFailed_ReturnFailingMessage()
        {
            // Arrange
            UserCreationRequest request = new UserCreationRequest
            {
                Email = "nana@hotmail.com",
                Login = "nani",
                Password = "screwyouPass"
            };
            string errorMessage = "hate my life";
            IdentityResult identityResult = IdentityResult.Failed(new IdentityError
            {
                Code = "23",
                Description = errorMessage
            });
            _userManagerMock.Setup(mock => mock.CreateAsync(It.Is<User>(user => user.Email == request.Email
                && user.UserName == request.Login), request.Password)).ReturnsAsync(identityResult);

            // Act
            ResultMessage result = await _identityService.CreateUserAsync(request).ConfigureAwait(false);

            // Assert
            Assert.NotNull(result);
            Assert.False(result.OperationStatus);
            Assert.Equal(errorMessage, result.ErrorMessages.First());
        }

        /// <summary>
        /// Given request is null
        /// When deleting user
        /// throw <see cref="ArgumentNullException"/> exception
        /// </summary>
        [Fact]
        public async Task DeleteUserAsync_RequestIsNull_ThrowArgumentNullException()
        {
            // Arrange
            DeleteUserRequest request = null;

            // Act + Assert
            ArgumentNullException exception =
                await Assert.ThrowsAsync<ArgumentNullException>(() => _identityService.DeleteUserAsync(request))
                .ConfigureAwait(false);
            Assert.NotNull(exception);
            Assert.Equal(string.Format(ErrorMessages.NullExceptionMessage, "request"), exception.Message);
        }

        /// <summary>
        /// Given request is not null
        /// And user isn't admin
        /// and deletion is done successfully
        /// When deleting user
        /// return success message
        /// </summary>
        [Fact]
        public async Task DeleteUserAsync_NotNullRequest_UserNotAdmin_OkDeletion_ReturnSuccessMessage()
        {
            // Arrange
            DeleteUserRequest request = new DeleteUserRequest
            {
                Login = "haw-haw"
            };
            User identityUser = new User
            {
                UserName = request.Login
            };
            _userManagerMock.Setup(mock => mock.FindByNameAsync(request.Login)).ReturnsAsync(identityUser);
            _userManagerMock.Setup(mock => mock.GetRolesAsync(identityUser)).ReturnsAsync(
                new List<string> { "hawRole" });
            _userManagerMock.Setup(mock => mock.DeleteAsync(identityUser)).ReturnsAsync(IdentityResult.Success);

            // Act
            ResultMessage resultMessage = await _identityService.DeleteUserAsync(request).ConfigureAwait(false);

            // Assert
            Assert.NotNull(resultMessage);
            Assert.True(resultMessage.OperationStatus);
        }

        /// <summary>
        /// Given request is not null
        /// And user is admin
        /// When deleting user
        /// return failing message
        /// </summary>
        [Fact]
        public async Task DeleteUserAsync_NotNullRequest_UserAdmin_ReturnFailingMessage()
        {
            // Arrange
            DeleteUserRequest request = new DeleteUserRequest
            {
                Login = "haw-haw"
            };
            User identityUser = new User
            {
                UserName = request.Login
            };
            _userManagerMock.Setup(mock => mock.FindByNameAsync(request.Login)).ReturnsAsync(identityUser);
            _userManagerMock.Setup(mock => mock.GetRolesAsync(identityUser)).ReturnsAsync(
                new List<string> { "ADMINISTRATOR" });

            // Act
            ResultMessage resultMessage = await _identityService.DeleteUserAsync(request).ConfigureAwait(false);

            // Assert
            Assert.NotNull(resultMessage);
            Assert.False(resultMessage.OperationStatus);
            Assert.Equal(MessageResources.DeleteAdministrator,
                resultMessage.ErrorMessages.First());
        }

        /// <summary>
        /// Given request is not null
        /// And user isn't admin
        /// And deletion failed
        /// When deleting user
        /// return failing message
        /// </summary>
        [Fact]
        public async Task DeleteUserAsync_NotNullRequest_UserNotAdmin_FailedDeletion_ReturnFailingMessage()
        {
            // Arrange
            DeleteUserRequest request = new DeleteUserRequest
            {
                Login = "haw-haw"
            };
            User identityUser = new User
            {
                UserName = request.Login
            };
            string errorMessage = "nelson: haw haw";
            _userManagerMock.Setup(mock => mock.FindByNameAsync(request.Login)).ReturnsAsync(identityUser);
            _userManagerMock.Setup(mock => mock.GetRolesAsync(identityUser)).ReturnsAsync(
                new List<string> { "hawRole" });
            _userManagerMock.Setup(mock => mock.DeleteAsync(identityUser)).ReturnsAsync(IdentityResult.Failed(
                new IdentityError { Description = errorMessage }));

            // Act
            ResultMessage resultMessage = await _identityService.DeleteUserAsync(request).ConfigureAwait(false);

            // Assert
            Assert.NotNull(resultMessage);
            Assert.False(resultMessage.OperationStatus);
            Assert.Equal(errorMessage, resultMessage.ErrorMessages.First());
        }

        /// <summary>
        /// Given null request
        /// when assigning a role to user
        /// throw <see cref="ArgumentNullException"/> exception
        /// </summary>
        [Fact]
        public async Task AssignRoleToUserAsync_RequestNull_ThrowArgumentNullException()
        {
            // Arrange
            UserRoleAssignmentRequest request = null;

            // Act + Assert
            ArgumentNullException exception = await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _identityService.AssignRoleToUserAsync(request)).ConfigureAwait(false);
            Assert.NotNull(exception);
            Assert.Equal(string.Format(ErrorMessages.NullExceptionMessage, "request"), exception.Message);
        }

        /// <summary>
        /// Given not null request
        /// and assignment operation is done successfully
        /// when assigning a role to user
        /// Return succcess message
        /// </summary>
        [Fact]
        public async Task AssignRoleToUserAsync_RequestNotNull_SuccessfulAssignment_ReturnSuccessMessage()
        {
            // Arrange
            UserRoleAssignmentRequest request = new UserRoleAssignmentRequest
            {
                Login = "nelson",
                RoleName = "bully"
            };
            User identityUser = new User
            {
                UserName = request.Login
            };
            _userManagerMock.Setup(mock => mock.FindByNameAsync(request.Login)).ReturnsAsync(identityUser);
            _userManagerMock.Setup(mock => mock.AddToRoleAsync(identityUser, request.RoleName)).ReturnsAsync(
                IdentityResult.Success);

            // Act
            ResultMessage resultMessage = await _identityService.AssignRoleToUserAsync(request).ConfigureAwait(false);

            // Assert
            Assert.NotNull(resultMessage);
            Assert.True(resultMessage.OperationStatus);
        }

        /// <summary>
        /// Given not null request
        /// and assignment operation has failed
        /// when assigning a role to user
        /// Return error message
        /// </summary>
        [Fact]
        public async Task AssignRoleToUserAsync_RequestNotNull_FailingAssignment_ReturnErrorMessage()
        {
            // Arrange
            UserRoleAssignmentRequest request = new UserRoleAssignmentRequest
            {
                Login = "nelson",
                RoleName = "bully"
            };
            User identityUser = new User
            {
                UserName = request.Login
            };
            string errorMessage = "haw-haw";
            _userManagerMock.Setup(mock => mock.FindByNameAsync(request.Login)).ReturnsAsync(identityUser);
            _userManagerMock.Setup(mock => mock.AddToRoleAsync(identityUser, request.RoleName)).ReturnsAsync(
                IdentityResult.Failed(new IdentityError { Description = errorMessage }));

            // Act
            ResultMessage resultMessage = await _identityService.AssignRoleToUserAsync(request).ConfigureAwait(false);

            // Assert
            Assert.NotNull(resultMessage);
            Assert.False(resultMessage.OperationStatus);
            Assert.Equal(errorMessage, resultMessage.ErrorMessages.First());
        }

        /// <summary>
        /// Given null request
        /// when unassigning a user from a role
        /// throw <see cref="ArgumentNullException"/> exception
        /// </summary>
        [Fact]
        public async Task UnassignRoleToUserAsync_RequestNull_ThrowArgumentNullException()
        {
            // Arrange
            UserRoleAssignmentRequest request = null;

            // Act + Assert
            ArgumentNullException exception = await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _identityService.UnassignRoleToUserAsync(request)).ConfigureAwait(false);
            Assert.NotNull(exception);
            Assert.Equal(string.Format(ErrorMessages.NullExceptionMessage, "request"), exception.Message);
        }

        /// <summary>
        /// Given null request
        /// when unassigning a user from a role
        /// throw <see cref="ArgumentNullException"/> exception
        /// </summary>
        [Fact]
        public async Task UnassignRoleToUserAsync_RequestNotNull_AdminRole_ThrowArgumentNullException()
        {
            // Arrange
            UserRoleAssignmentRequest request = new UserRoleAssignmentRequest
            {
                Login = "skinner",
                RoleName = "ADMINISTRATOR"
            };

            // Act
            ResultMessage result = await _identityService.UnassignRoleToUserAsync(request).ConfigureAwait(false);

            // Assert
            Assert.NotNull(result);
            Assert.False(result.OperationStatus);
            Assert.Equal(MessageResources.UnassignAdminRole,
                result.ErrorMessages.First());
        }

        /// <summary>
        /// Given not null request
        /// and unassignment operation is done successfully
        /// when unassigning a user from a role
        /// Return succcess message
        /// </summary>
        [Fact]
        public async Task UnassignRoleToUserAsync_RequestNotNull_SuccessfulAssignment_ReturnSuccessMessage()
        {
            // Arrange
            UserRoleAssignmentRequest request = new UserRoleAssignmentRequest
            {
                Login = "nelson",
                RoleName = "bully"
            };
            User identityUser = new User
            {
                UserName = request.Login
            };
            _userManagerMock.Setup(mock => mock.FindByNameAsync(request.Login)).ReturnsAsync(identityUser);
            _userManagerMock.Setup(mock => mock.RemoveFromRoleAsync(identityUser, request.RoleName)).ReturnsAsync(
                IdentityResult.Success);

            // Act
            ResultMessage resultMessage = await _identityService.UnassignRoleToUserAsync(request).ConfigureAwait(false);

            // Assert
            Assert.NotNull(resultMessage);
            Assert.True(resultMessage.OperationStatus);
        }

        /// <summary>
        /// Given not null request
        /// and unassignment operation has failed
        /// when unassigning a user from a role
        /// Return error message
        /// </summary>
        [Fact]
        public async Task UnassignRoleToUserAsync_RequestNotNull_FailingAssignment_ReturnErrorMessage()
        {
            // Arrange
            UserRoleAssignmentRequest request = new UserRoleAssignmentRequest
            {
                Login = "nelson",
                RoleName = "bully"
            };
            User identityUser = new User
            {
                UserName = request.Login
            };
            string errorMessage = "haw-haw";
            _userManagerMock.Setup(mock => mock.FindByNameAsync(request.Login)).ReturnsAsync(identityUser);
            _userManagerMock.Setup(mock => mock.RemoveFromRoleAsync(identityUser, request.RoleName)).ReturnsAsync(
                IdentityResult.Failed(new IdentityError { Description = errorMessage }));

            // Act
            ResultMessage resultMessage = await _identityService.UnassignRoleToUserAsync(request).ConfigureAwait(false);

            // Assert
            Assert.NotNull(resultMessage);
            Assert.False(resultMessage.OperationStatus);
            Assert.Equal(errorMessage, resultMessage.ErrorMessages.First());
        }

        /// <summary>
        /// Given null request
        /// when initializing user password
        /// throw <see cref="ArgumentNullException"/> exception
        /// </summary>
        [Fact]
        public async Task InitializeUserPassword_RequestNull_ThrowArgumentNullException()
        {
            // Arrange
            PasswordInitializationRequest request = null;

            // Act + Assert
            ArgumentNullException exception = await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _identityService.InitializeUserPasswordAsync(request)).ConfigureAwait(false);
            Assert.NotNull(exception);
            Assert.Equal(string.Format(ErrorMessages.NullExceptionMessage, "request"), exception.Message);
        }

        /// <summary>
        /// Given not null request
        /// And user role is admin
        /// when initializing user password
        /// return error message
        /// </summary>
        [Fact]
        public async Task InitializeUserPassword_NotNullRequest_AdminRole_ReturnErrorMessage()
        {
            // Arrange
            PasswordInitializationRequest request = new PasswordInitializationRequest
            {
                Login = "skinner",
                NewPassword = "skinnerIsNotWienner",
                OldPassword = "skinnerIsWienner"
            };
            User identityUser = new User
            {
                UserName = request.Login
            };
            _userManagerMock.Setup(mock => mock.FindByNameAsync(request.Login)).ReturnsAsync(identityUser);
            _userManagerMock.Setup(mock => mock.GetRolesAsync(identityUser)).ReturnsAsync(new List<string>
                { "ADMINISTRATOR" });


            // Act
            ResultMessage result = await _identityService.InitializeUserPasswordAsync(request).ConfigureAwait(false);

            // Assert
            Assert.NotNull(result);
            Assert.False(result.OperationStatus);
            Assert.Equal(MessageResources.ReinitializeAdminPassword,
                result.ErrorMessages.First());
        }

        /// <summary>
        /// Given not null request
        /// And user role is not admin
        /// and operation is executed successfully
        /// when initializing user password
        /// return success message
        /// </summary>
        [Fact]
        public async Task InitializeUserPassword_NotNullRequest_NotAdminRole_SuccessOperation_ReturnSuccessMessage()
        {
            // Arrange
            PasswordInitializationRequest request = new PasswordInitializationRequest
            {
                Login = "bart",
                NewPassword = "elBarto253",
                OldPassword = "elBarto659"
            };
            User identityUser = new User
            {
                UserName = request.Login
            };
            _userManagerMock.Setup(mock => mock.FindByNameAsync(request.Login)).ReturnsAsync(identityUser);
            _userManagerMock.Setup(mock => mock.GetRolesAsync(identityUser)).ReturnsAsync(new List<string>
                { "littleKid" });
            _userManagerMock.Setup(mock => mock.RemovePasswordAsync(identityUser)).ReturnsAsync(IdentityResult.Success);
            _userManagerMock.Setup(mock => mock.AddPasswordAsync(identityUser, request.NewPassword)).ReturnsAsync(IdentityResult.Success);

            // Act
            ResultMessage result = await _identityService.InitializeUserPasswordAsync(request).ConfigureAwait(false);

            // Assert
            Assert.NotNull(result);
            Assert.True(result.OperationStatus);
        }

        /// <summary>
        /// Given not null request
        /// And user role is not admin
        /// and removing old password is not executed successfully
        /// when initializing user password
        /// return error message
        /// </summary>
        [Fact]
        public async Task InitializeUserPassword_NotNullRequest_NotAdminRole_FailingOldPasswordRemoving_ReturnErrorMessage()
        {
            // Arrange
            PasswordInitializationRequest request = new PasswordInitializationRequest
            {
                Login = "bart",
                NewPassword = "elBarto253",
                OldPassword = "elBarto659"
            };
            User identityUser = new User
            {
                UserName = request.Login
            };
            string errorMessage = "you suck";
            _userManagerMock.Setup(mock => mock.FindByNameAsync(request.Login)).ReturnsAsync(identityUser);
            _userManagerMock.Setup(mock => mock.GetRolesAsync(identityUser)).ReturnsAsync(new List<string>
                { "littleKid" });
            _userManagerMock.Setup(mock => mock.RemovePasswordAsync(identityUser)).ReturnsAsync(
                IdentityResult.Failed(new IdentityError { Description = errorMessage }));

            // Act
            ResultMessage result = await _identityService.InitializeUserPasswordAsync(request).ConfigureAwait(false);

            // Assert
            Assert.NotNull(result);
            Assert.False(result.OperationStatus);
            Assert.Equal(errorMessage, result.ErrorMessages.First());
        }

        /// <summary>
        /// Given not null request
        /// And user role is not admin
        /// and adding new password has failed
        /// when initializing user password
        /// return error message
        /// </summary>
        [Fact]
        public async Task InitializeUserPassword_NotNullRequest_NotAdminRole_AddNewPasswordFailed_ReturnErrorMessage()
        {
            // Arrange
            PasswordInitializationRequest request = new PasswordInitializationRequest
            {
                Login = "bart",
                NewPassword = "elBarto253",
                OldPassword = "elBarto659"
            };
            User identityUser = new User
            {
                UserName = request.Login
            };
            string errorMessage = "your password suck";
            _userManagerMock.Setup(mock => mock.FindByNameAsync(request.Login)).ReturnsAsync(identityUser);
            _userManagerMock.Setup(mock => mock.GetRolesAsync(identityUser)).ReturnsAsync(new List<string>
                { "littleKid" });
            _userManagerMock.Setup(mock => mock.RemovePasswordAsync(identityUser)).ReturnsAsync(IdentityResult.Success);
            _userManagerMock.Setup(mock => mock.AddPasswordAsync(identityUser, request.NewPassword)).ReturnsAsync(
                IdentityResult.Failed(new IdentityError { Description = errorMessage }));

            // Act
            ResultMessage result = await _identityService.InitializeUserPasswordAsync(request).ConfigureAwait(false);

            // Assert
            Assert.NotNull(result);
            Assert.False(result.OperationStatus);
            Assert.Equal(errorMessage, result.ErrorMessages.First());
        }

        /// <summary>
        /// Given null request
        /// when updating user password
        /// throw <see cref="ArgumentNullException"/> exception
        /// </summary>
        [Fact]
        public async Task UpdateUserPasswordAsync_RequestNull_ThrowArgumentNullException()
        {
            // Arrange
            PasswordInitializationRequest request = null;

            // Act + Assert
            ArgumentNullException exception = await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _identityService.UpdateUserPasswordAsync(request)).ConfigureAwait(false);
            Assert.NotNull(exception);
            Assert.Equal(string.Format(ErrorMessages.NullExceptionMessage, "request"), exception.Message);
        }

        /// <summary>
        /// Given not null request
        /// and password update is sucessful
        /// when updating user password
        /// return success message
        /// </summary>
        [Fact]
        public async Task UpdateUserPasswordAsync_RequestNotNull_SuccessfulUpdate_ReturnSuccessMessage()
        {
            // Arrange
            PasswordInitializationRequest request = new PasswordInitializationRequest
            {
                Login = "Homer",
                OldPassword = "Hold my beer",
                NewPassword = "thank you moe"
            };
            User identityUser = new User
            {
                UserName = request.Login
            };
            _userManagerMock.Setup(mock => mock.FindByNameAsync(request.Login)).ReturnsAsync(identityUser);
            _userManagerMock.Setup(mock => mock.ChangePasswordAsync(identityUser, request.OldPassword, request.NewPassword))
                .ReturnsAsync(IdentityResult.Success);

            // Act
            ResultMessage resultMessage = await _identityService.UpdateUserPasswordAsync(request).ConfigureAwait(false);

            // Assert
            Assert.NotNull(resultMessage);
            Assert.True(resultMessage.OperationStatus);
        }

        /// <summary>
        /// Given not null request
        /// and password update has failed
        /// when updating user password
        /// return error message
        /// </summary>
        [Fact]
        public async Task UpdateUserPasswordAsync_RequestNotNull_FailingUpdate_ReturnErrorMessage()
        {
            // Arrange
            PasswordInitializationRequest request = new PasswordInitializationRequest
            {
                Login = "Homer",
                OldPassword = "Hold my beer",
                NewPassword = "thank you moe"
            };
            User identityUser = new User
            {
                UserName = request.Login
            };
            string errorMessage = "stupid flanders";
            _userManagerMock.Setup(mock => mock.FindByNameAsync(request.Login)).ReturnsAsync(identityUser);
            _userManagerMock.Setup(mock => mock.ChangePasswordAsync(identityUser, request.OldPassword, request.NewPassword))
                .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = errorMessage }));

            // Act
            ResultMessage resultMessage = await _identityService.UpdateUserPasswordAsync(request).ConfigureAwait(false);

            // Assert
            Assert.NotNull(resultMessage);
            Assert.False(resultMessage.OperationStatus);
            Assert.Equal(errorMessage, resultMessage.ErrorMessages.First());
        }

        /// <summary>
        /// Given user manager returns users
        /// when getting users list
        /// return user list message
        /// </summary>
        [Fact]
        public void Users_GivenUserManagerReturnsUsers_ReturnUserListMessage()
        {
            // Arrange
            List<User> usersList = new List<User>
            {
                new User
                {
                    UserName = "sla",
                    Email = "sla@gmail.com",
                    CreationDate = DateTime.Now,
                    UpdateDate = DateTime.Now
                }
            };
            _userManagerMock.Setup(mock => mock.Users).Returns(usersList.AsQueryable());

            // Act
            UsersListMessage resultMessage = _identityService.Users;

            // Assert
            Assert.NotNull(resultMessage);
            Assert.True(resultMessage.OperationStatus);
            Assert.NotEmpty(resultMessage.Users);
            Assert.True(resultMessage.Users.Select(u => u.Login).SequenceEqual(usersList.Select(u => u.UserName)));
            Assert.True(resultMessage.Users.Select(u => u.Email).SequenceEqual(usersList.Select(u => u.Email)));
        }

        /// <summary>
        /// Given role manager returns roles
        /// when getting roles list
        /// return roles list message
        /// </summary>
        [Fact]
        public void Roles_GivenRoleManagerReturnsRoles_ReturnRolesListMessage()
        {
            // Arrange
            List<Role> rolesList = new List<Role>
            {
                new Role
                {
                    Name = "yeet",
                    CreationDate = DateTime.Now,
                    UpdateDate = DateTime.Now
                }
            };
            _roleManagerMock.Setup(mock => mock.Roles).Returns(rolesList.AsQueryable());

            // Act
            RolesListMessage resultMessage = _identityService.Roles;

            // Assert
            Assert.NotNull(resultMessage);
            Assert.True(resultMessage.OperationStatus);
            Assert.NotEmpty(resultMessage.Roles);
            Assert.True(resultMessage.Roles.Select(u => u.Name).SequenceEqual(rolesList.Select(u => u.Name)));
        }
    }
}
