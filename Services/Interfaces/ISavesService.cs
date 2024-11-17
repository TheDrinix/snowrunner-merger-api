using SnowrunnerMergerApi.Models.Saves;
using SnowrunnerMergerApi.Models.Saves.Dtos;

namespace SnowrunnerMergerApi.Services.Interfaces;

public interface ISavesService
{
    /// <summary>
    /// Stores a save file for a specified group.
    /// </summary>
    /// <param name="groupId">The ID of the group to store the save file for.</param>
    /// <param name="data">An <see cref="UploadSaveDto"/> object containing the save file and its metadata.</param>
    /// <param name="saveSlot">The slot number to store the save file in.</param>
    /// <returns>A <see cref="StoredSaveInfo"/> object containing information about the stored save file.</returns>
    Task<StoredSaveInfo> StoreSave(Guid groupId, UploadSaveDto data, int saveSlot);
    /// <summary>
    ///     Merges two save files from a group and returns the path to the merged save file.
    /// </summary>
    /// <param name="groupId">The ID of the group to merge the save files for.</param>
    /// <param name="data">A <see cref="MergeSavesDto"/> object containing the save file to merge and its metadata.</param>
    /// <param name="storedSaveNumber">The slot number of the stored save file to merge with.</param>
    /// <returns>The path to the merged save file.</returns>
    Task<string> MergeSaves(Guid groupId, MergeSavesDto data, int storedSaveNumber);
    /// <summary>
    ///     Removes a save file from a group.
    /// </summary>
    /// <param name="saveId">The ID of the save file to remove.</param>
    Task RemoveSave(Guid saveId);
    /// <summary>
    ///     Removes stored save data from the database and the file system.
    /// </summary>
    /// <param name="save">The <see cref="StoredSaveInfo"/> object to remove.</param>
    Task RemoveSave(StoredSaveInfo save);
}