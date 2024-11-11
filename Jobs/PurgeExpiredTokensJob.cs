using Quartz;
using SnowrunnerMergerApi.Data;

namespace SnowrunnerMergerApi.Jobs;

public class PurgeExpiredTokensJob(AppDbContext dbContext) : IJob
{
    public async Task Execute(IJobExecutionContext context)
    {
        var expiredTokens = dbContext.UserTokens.Where(x => x.ExpiresAt < DateTime.UtcNow).ToList();
        
        dbContext.UserTokens.RemoveRange(expiredTokens);
        await dbContext.SaveChangesAsync();
    }
}