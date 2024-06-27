using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace SnowrunnerMergerApi.Exceptions;

public class HttpResponseExceptionFilter : IActionFilter, IOrderedFilter
{
    public int Order => int.MaxValue - 10;

    public void OnActionExecuting(ActionExecutingContext filterContext) { }

    public void OnActionExecuted(ActionExecutedContext filterContext)
    {
        if (filterContext.Exception is HttpResponseException httpResponseException)
        {
            filterContext.Result = new ObjectResult(httpResponseException.GetValue)
            {
                StatusCode = (int)httpResponseException.StatusCode,
            };

            filterContext.ExceptionHandled = true;
        }
    }
}