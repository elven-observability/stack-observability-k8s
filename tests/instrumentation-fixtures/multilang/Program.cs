using System.Text.Json;
var builder=WebApplication.CreateBuilder(args);builder.Logging.ClearProviders();
var app=builder.Build();app.MapGet("/ready",()=>Results.Json(new{ok=true,runtime=Environment.Version.ToString()}));
app.MapGet("/exercise",(HttpContext context)=>{
 var parts=context.Request.Headers["traceparent"].ToString().Split('-');var tid=parts.Length==4?parts[1]:"";
 Console.WriteLine(JsonSerializer.Serialize(new{message="Synthetic checkout approved",run="elven-saas-20261116",trace_id=tid,email="synthetic-customer@example.invalid",password="synth-password-20261116"}));
 return Results.Json(new{ok=true,runtime=Environment.Version.ToString(),traceId=tid});});app.Run("http://0.0.0.0:8080");
