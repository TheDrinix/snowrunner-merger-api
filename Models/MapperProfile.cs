using AutoMapper;
using SnowrunnerMergerApi.Models.Auth;
using SnowrunnerMergerApi.Models.Saves;
using SnowrunnerMergerApi.Models.Saves.Dtos;

namespace SnowrunnerMergerApi.Models;

public class MapperProfile : Profile
{
    public MapperProfile()
    {
        CreateMap<User, GroupMemberDto>();
        CreateMap<SaveGroup, GroupDto>();
    }
}