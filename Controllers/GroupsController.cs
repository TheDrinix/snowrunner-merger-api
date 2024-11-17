using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SnowrunnerMergerApi.Models.Auth.Dtos;
using SnowrunnerMergerApi.Models.Saves;
using SnowrunnerMergerApi.Models.Saves.Dtos;
using SnowrunnerMergerApi.Services;
using SnowrunnerMergerApi.Services.Interfaces;
using Swashbuckle.AspNetCore.Annotations;

namespace SnowrunnerMergerApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize] 
    public class GroupsController(
        IUserService userService,
        IGroupsService groupsService,
        ISavesService savesService,
        IMapper mapper) : ControllerBase
    {
        [HttpGet]
        [SwaggerOperation(Summary = "Get user groups", Description = "Get all groups user is a member of")]
        [SwaggerResponse(StatusCodes.Status200OK, "Groups list", typeof(ICollection<GroupDto>))]
        [SwaggerResponse(StatusCodes.Status401Unauthorized)]
        public async Task<ActionResult<ICollection<GroupDto>>> GetGroups()
        {
            var sessionData = userService.GetUserSessionData();

            var groups = await groupsService.GetUserGroups(sessionData.Id);
            
            return Ok(mapper.Map<ICollection<GroupDto>>(groups));
        }
        
        [HttpGet("{groupId:guid}")]
        [SwaggerOperation(Summary = "Get group", Description = "Get group data by id")]
        [SwaggerResponse(StatusCodes.Status200OK, "Group data", typeof(GroupDto))]
        [SwaggerResponse(StatusCodes.Status401Unauthorized)]
        [SwaggerResponse(StatusCodes.Status404NotFound, "Group not found")]
        public async Task<ActionResult<GroupDto>> GetGroup(Guid groupId)
        {
            var sessionData = userService.GetUserSessionData();
            
            var group = await groupsService.GetGroupData(groupId, sessionData.Id);
            
            if (group is null) return NotFound();
            
            return Ok(mapper.Map<GroupDto>(group));
        }
        
        [HttpGet("{groupId:guid}/saves")]
        [SwaggerOperation(Summary = "Get group saves", Description = "Get list of saves uploaded to the group")]
        [SwaggerResponse(StatusCodes.Status200OK, "Saves list", typeof(ICollection<StoredSaveInfo>))]
        [SwaggerResponse(StatusCodes.Status401Unauthorized)]
        [SwaggerResponse(StatusCodes.Status404NotFound, "Group not found")]
        public async Task<ActionResult<ICollection<StoredSaveInfo>>> GetGroupSaves(Guid groupId)
        {
            var sessionData = userService.GetUserSessionData();
            
            var group = await groupsService.GetGroupData(groupId, sessionData.Id);
            
            if (group is null) return NotFound();

            var saves = group.StoredSaves.OrderByDescending(s => s.UploadedAt);
            
            return Ok(saves);
        }
        
        [HttpPost]
        [SwaggerOperation(Summary = "Create group", Description = "Create a new group")]
        [SwaggerResponse(StatusCodes.Status200OK, "Group data", typeof(SaveGroup))]
        [SwaggerResponse(StatusCodes.Status401Unauthorized)]
        [SwaggerResponse(StatusCodes.Status403Forbidden, "User is not authorized to create a group")]
        public async Task<ActionResult<SaveGroup>> CreateGroup([FromBody] CreateGroupDto data)
        {
            var sessionData = userService.GetUserSessionData();
            
            var group = await groupsService.CreateGroup(data.Name, sessionData.Id);
            
            return Ok(group);
        }
        
        [HttpPost("{groupId:guid}/join")]
        [SwaggerOperation(Summary = "Join group", Description = "Join an existing group")]
        [SwaggerResponse(StatusCodes.Status200OK, "Group data", typeof(GroupDto))]
        [SwaggerResponse(StatusCodes.Status401Unauthorized)]
        [SwaggerResponse(StatusCodes.Status404NotFound, "Group not found")]
        public async Task<ActionResult<GroupDto>> JoinGroup(Guid groupId)
        {
            var sessionData = userService.GetUserSessionData();
            
            var group = await groupsService.JoinGroup(groupId, sessionData.Id);
            
            return Ok(mapper.Map<GroupDto>(group));
        }
        
        [HttpDelete("{groupId:guid}/leave")]
        [SwaggerOperation(Summary = "Leave group", Description = "Leave a group")]
        [SwaggerResponse(StatusCodes.Status204NoContent)]
        [SwaggerResponse(StatusCodes.Status401Unauthorized)]
        [SwaggerResponse(StatusCodes.Status404NotFound, "Group not found")]
        public async Task<IActionResult> LeaveGroup([SwaggerParameter("The unique group identifier")] Guid groupId)
        {
            await groupsService.LeaveGroup(groupId);
            
            return NoContent();
        }

        [HttpPost("{groupId:guid}/upload")]
        [SwaggerOperation(Summary = "Upload save", Description = "Upload a save to the group")]
        [SwaggerResponse(StatusCodes.Status200OK, "Stored save info", typeof(StoredSaveInfo))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Uploaded data are invalid or too large")]
        [SwaggerResponse(StatusCodes.Status401Unauthorized)]
        [SwaggerResponse(StatusCodes.Status404NotFound, "Group not found")]
        public async Task<IActionResult> UploadSave([FromRoute] Guid groupId, [FromForm] UploadSaveDto data, [FromQuery] int saveSlot = -1)
        {
            if (data.Save.Length > SavesService.MaxSaveSize) return BadRequest();
            
            var save = await savesService.StoreSave(groupId, data, saveSlot);
            
            return Ok(save);
        }

        [HttpPost("{groupid:guid}/merge")]
        [SwaggerOperation(Summary = "Merge saves", Description = "Merge uploaded save with a stored one in the group")]
        [SwaggerResponse(StatusCodes.Status200OK, "Merged save", typeof(FileContentResult))]
        [SwaggerResponse(StatusCodes.Status400BadRequest, "Uploaded data are invalid or too large")]
        [SwaggerResponse(StatusCodes.Status401Unauthorized)]
        [SwaggerResponse(StatusCodes.Status404NotFound, "Group not found")]
        public async Task<IActionResult> MergeSaves([FromRoute] Guid groupId, [FromForm] MergeSavesDto data, [FromQuery] int storedSaveNumber = 0)
        {
            var saveZipPath = await savesService.MergeSaves(groupId, data, storedSaveNumber);

            var fs = new FileStream(saveZipPath, FileMode.Open, FileAccess.Read, FileShare.None, 4096,
                FileOptions.DeleteOnClose);

            return File(fs, contentType: "application/zip", fileDownloadName: "output.zip");
        }

        [HttpDelete("{groupId:guid}/saves/{saveId:guid}")]
        [SwaggerOperation(Summary = "Delete save", Description = "Delete a save from the group")]
        [SwaggerResponse(StatusCodes.Status204NoContent)]
        [SwaggerResponse(StatusCodes.Status401Unauthorized)]
        [SwaggerResponse(StatusCodes.Status404NotFound, "Group or save not found")]
        public async Task<IActionResult> DeleteSave(Guid saveId)
        {
            await savesService.RemoveSave(saveId);
            
            return NoContent();
        }
        
        [HttpDelete("{groupId:guid}")]
        [SwaggerOperation(Summary = "Delete group", Description = "Delete a group")]
        [SwaggerResponse(StatusCodes.Status204NoContent)]
        [SwaggerResponse(StatusCodes.Status401Unauthorized)]
        [SwaggerResponse(StatusCodes.Status404NotFound, "Group not found")]
        public async Task<IActionResult> DeleteGroup(Guid groupId)
        {
            await groupsService.RemoveGroup(groupId);
            
            return NoContent();
        }
    }
}
