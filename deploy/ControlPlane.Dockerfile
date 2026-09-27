FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /source
COPY global.json .
COPY src ./src
RUN dotnet publish src/ControlPlane/EdgeVpn.ControlPlane.csproj -c Release -o /out --self-contained false
FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /out .
ENV ASPNETCORE_URLS=http://127.0.0.1:5080 DataDirectory=/data
USER $APP_UID
ENTRYPOINT ["dotnet", "EdgeVpn.ControlPlane.dll"]
