using SnowrunnerMergerApi.Models.Saves;
using SnowrunnerMergerApi.Models.Saves.Dtos;

namespace SnowrunnerMergerApi.Services;

public interface ISavesService
{
    Task<StoredSaveInfo> StoreSave(Guid groupId, UploadSaveDto data, int saveSlot);
    Task<string> MergeSaves(Guid groupId, MergeSavesDto data, int storedSaveNumber);
    Task RemoveSave(Guid saveId);
    Task RemoveSave(StoredSaveInfo save);
}