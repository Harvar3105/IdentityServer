FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /app

COPY IdentityServer/IdentityServer.csproj ./IdentityServer/

WORKDIR /app/IdentityServer
RUN dotnet restore

COPY IdentityServer/. ./ 

RUN dotnet publish -c Release -o /out

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /out .

ENTRYPOINT ["dotnet", "IdentityServer.dll"]
