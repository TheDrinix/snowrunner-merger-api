using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SnowrunnerMergerApi.Models.Auth.Dtos;
using SnowrunnerMergerApi.Models.Saves;
using SnowrunnerMergerApi.Models.Saves.Dtos;
using SnowrunnerMergerApi.Services;

namespace SnowrunnerMergerApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize] 
    public class GroupsController(
        IAuthService authService, 
        IGroupsService groupsService,
        ISavesService savesService) : ControllerBase
    {
        [HttpGet]
        public async Task<ActionResult<ICollection<SaveGroup>>> GetGroups()
        {
            var sessionData = authService.GetUserSessionData();

            var groups = await groupsService.GetUserGroups(sessionData.Id);
            
            return Ok(groups);
        }
        
        [HttpGet("{groupId}")]
        public async Task<ActionResult<SaveGroup>> GetGroup(Guid groupId)
        {
            var sessionData = authService.GetUserSessionData();
            
            var group = await groupsService.GetGroupData(groupId, sessionData.Id);
            
            if (group is null) return NotFound();
            
            return Ok(group);
        }
        
        [HttpPost]
        public async Task<ActionResult<SaveGroup>> CreateGroup([FromBody] CreateGroupDto data)
        {
            var sessionData = authService.GetUserSessionData();
            
            var group = await groupsService.CreateGroup(data.Name, sessionData.Id);
            
            return Ok(group);
        }
        
        [HttpPost("{groupId:guid}/join")]
        public async Task<ActionResult<SaveGroup>> JoinGroup(Guid groupId)
        {
            var sessionData = authService.GetUserSessionData();
            
            var group = await groupsService.JoinGroup(groupId, sessionData.Id);
            
            return Ok(group);
        }
        
        [HttpPost("{groupId:guid}/leave")]
        public async Task<IActionResult> LeaveGroup(Guid groupId)
        {
            await groupsService.LeaveGroup(groupId);
            
            return NoContent();
        }

        [HttpPost("{groupId:guid}/upload")]
        public async Task<IActionResult> UploadSave([FromRoute] Guid groupId, [FromForm] UploadSaveDto data)
        {
            if (data.Save.Length > SavesService.MaxSaveSize) return BadRequest();
            
            var save = await savesService.StoreSave(groupId, data);
            
            return Ok(save);
        }
    }
}
