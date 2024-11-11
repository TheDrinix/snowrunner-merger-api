using Quartz;
using SnowrunnerMergerApi.Data;

namespace SnowrunnerMergerApi.Jobs;

public class PurgeExpiredSessionsJob(AppDbContext dbContext) : IJob
{
    public async Task Execute(IJobExecutionContext context)
    {
        var expiredSessions = dbContext.UserSessions.Where(x => x.ExpiresAt < DateTime.UtcNow).ToList();
        
        dbContext.UserSessions.RemoveRange(expiredSessions);
        await dbContext.SaveChangesAsync();
    }
}