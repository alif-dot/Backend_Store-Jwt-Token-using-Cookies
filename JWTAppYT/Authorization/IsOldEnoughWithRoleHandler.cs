using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace JWTAppYT.Authorization
{
    public class IsOldEnoughWithRoleHandler : AuthorizationHandler<IsOldEnoughWithRoleRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, IsOldEnoughWithRoleRequirement requirement)
        {
            var bDay = context.User.Claims.Where(x => x.Type == ClaimTypes.DateOfBirth).FirstOrDefault().Value;
            var bDayObj = Convert.ToDateTime(bDay);

            DateTime now = DateTime.Today;
            int age = DateTime.Today.Year - bDayObj.Year;
            if (now < bDayObj.AddYears(age))
                age--;

            if (requirement.MinAge <= age && context.User.IsInRole("Admin"))
            {
                context.Succeed(requirement);
            }
            else
            {
                context.Fail();
            }
            return Task.CompletedTask;
        }
    }
}
