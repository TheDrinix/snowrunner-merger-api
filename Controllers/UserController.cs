using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SnowrunnerMergerApi.Models.Auth;
using SnowrunnerMergerApi.Models.Auth.Dtos;
using SnowrunnerMergerApi.Services;
using SnowrunnerMergerApi.Services.Interfaces;
using Swashbuckle.AspNetCore.Annotations;

namespace SnowrunnerMergerApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class UserController(IUserService userService) : ControllerBase
    {
        [HttpGet]
        [SwaggerOperation(Summary = "Get current user", Description = "Get data of the currently authenticated user")]
        [SwaggerResponse(StatusCodes.Status200OK, "User data", typeof(User))]
        [SwaggerResponse(StatusCodes.Status401Unauthorized)]
        public async Task<ActionResult<User>> GetCurrentUser()
        {
            var user = await userService.GetCurrentUser();

            return Ok(user);
        }

        [HttpPatch("password")]
        [SwaggerOperation(Summary = "Update password", Description = "Update the password of the currently authenticated user")]
        [SwaggerResponse(StatusCodes.Status200OK, "Updated user data", typeof(User))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "The new password does not meet the requirements")]
        [SwaggerResponse(StatusCodes.Status401Unauthorized)]
        public async Task<ActionResult<User>> UpdatePassword(UpdatePasswordDto data)
        {
            var updatedUser = await userService.UpdatePassword(data);

            return Ok(updatedUser);
        }
        
        [HttpPatch("username")]
        [SwaggerOperation(Summary = "Update username", Description = "Update the username of the currently authenticated user")]
        [SwaggerResponse(StatusCodes.Status200OK, "Updated user data", typeof(User))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "The new username does not meet the requirements")]
        [SwaggerResponse(StatusCodes.Status401Unauthorized)]
        public async Task<ActionResult<User>> UpdateUsername(UpdateUsernameDto data)
        {
            var updatedUser = await userService.UpdateUsername(data.Username);

            return Ok(updatedUser);
        }

        [HttpDelete]
        [SwaggerOperation(Summary = "Delete account", Description = "Delete the currently authenticated user account")]
        [SwaggerResponse(StatusCodes.Status204NoContent, "Account deleted")]
        [SwaggerResponse(StatusCodes.Status401Unauthorized)]
        public async Task<ActionResult> DeleteAccount()
        {
            await userService.DeleteUser();

            return NoContent();
        }
    }
}
