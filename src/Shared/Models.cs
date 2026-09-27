using System.Security.Cryptography;
using System.Text;
namespace EdgeVpn;

public sealed class Database
{
    public MailSettings Mail { get; set; } = new();
    public List<EmailChallenge> EmailChallenges { get; set; } = [];
    public List<Account> Accounts { get; set; } = [];
    public List<LoginSession> Sessions { get; set; } = [];
    public List<VpnNetwork> Networks { get; set; } = [];
    public List<JoinKey> JoinKeys { get; set; } = [];
    public List<InstallTicket> InstallTickets { get; set; } = [];
    public List<Device> Devices { get; set; } = [];
    public List<PlatformNode> Nodes { get; set; } = [];
    public List<AuditEvent> Audit { get; set; } = [];
}
public sealed record Account(string Id, string Email, string PasswordHash, string Salt)
{
    public bool IsAdmin { get; set; }
    public bool Disabled { get; set; }
    public DateTimeOffset? CreatedAt { get; set; }
    public DateTimeOffset? EmailVerifiedAt { get; set; }
    public DateTimeOffset? LastLoginAt { get; set; }
    public string RecoveryHash { get; set; } = "";
    public int FailedLogins { get; set; }
    public DateTimeOffset? LockedUntil { get; set; }
    public string Plan { get; set; } = "basic";
    public DateTimeOffset? PlanExpiresAt { get; set; }
}
public sealed record LoginSession(string Hash, string AccountId, DateTimeOffset ExpiresAt);
public sealed record VpnGroup(string Id, string Name);
public sealed class VpnNetwork
{
    public string Id { get; set; } = Secrets.Id();
    public string OwnerId { get; set; } = "";
    public string Name { get; set; } = "";
    public int Port { get; set; }
    public string Subnet { get; set; } = "10.77.0.0/16";
    public string SharedSecret { get; set; } = Secrets.Token();
    public string DataSecret { get; set; } = Secrets.Token();
    public List<VpnGroup> Groups { get; set; } = [];
}
public sealed class JoinKey
{
    public string Id { get; set; } = Secrets.Id();
    public string NetworkId { get; set; } = "";
    public string GroupId { get; set; } = "";
    public string Name { get; set; } = "";
    public string Hash { get; set; } = "";
    public DateTimeOffset ExpiresAt { get; set; }
    public int RemainingUses { get; set; }
    public bool Revoked { get; set; }
}
public sealed class Device
{
    public string Id { get; set; } = Secrets.Id();
    public string NetworkId { get; set; } = "";
    public string GroupId { get; set; } = "";
    public string Name { get; set; } = "";
    public string TokenHash { get; set; } = "";
    public string Address { get; set; } = "";
    public bool Revoked { get; set; }
    public DateTimeOffset? LastSeenAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
public sealed record AuditEvent(DateTimeOffset At, string Actor, string Action, string Target);
public sealed record NetworkSnapshot(string Id, int Port, string SharedSecret, Device[] Devices, string Subnet = "10.77.0.0/16");
public sealed record RelayIdentity(string DeviceId, string SessionId, ulong PeerId, string Address, int BytesPerSecond, int PrefixLength = 16);
public sealed record NodeSnapshot(DateTimeOffset At, NetworkSnapshot[] Networks);
public sealed record LoginRequest(string Email, string Password, string? VerificationCode = null);
public sealed record NameRequest(string Name, string? Subnet = null);
public sealed record KeyRequest(string Name, string GroupId, int Uses = 1, int ValidHours = 24);
public sealed record EnrollRequest(string Key, string Name);
public sealed record PlanRequest(string Plan, DateTimeOffset? ExpiresAt);
public sealed record InspectRequest(string Token);
public sealed record ClientProfile(string Server, string Group, string SharedSecret, string DeviceId,
    string DeviceToken, string ControlUrl, string[] CoordinatorServers, string[] RelayUrls, string DataSecret,
    bool EnableAutoUpdate = false, bool EnableUpnp = true, string TraversalMode = "eager", string AdapterName = "Edge VPN", string Subnet = "10.77.0.0/16");
public sealed class PlanOptions
{
    public bool RelayEnabled { get; set; }
    public int MaxNetworks { get; set; } = 3;
    public int MaxDevices { get; set; } = 20;
    public int RelayBytesPerSecond { get; set; } = 1048576;
}
public static class Secrets
{
    public static string Id() => Guid.NewGuid().ToString("N");
    public static string Token() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    public static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    public static bool Equal(string first, string second) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(Hash(first)), Encoding.UTF8.GetBytes(Hash(second)));
    public static string Password(string password, string salt) => Convert.ToBase64String(
        Rfc2898DeriveBytes.Pbkdf2(password, Convert.FromBase64String(salt), 210000, HashAlgorithmName.SHA512, 32));
    public static string Session(Device device) => device.NetworkId + "/" + device.GroupId;
    public static string GroupDataKey(VpnNetwork network, string groupId) => Convert.ToBase64String(
        HMACSHA256.HashData(Convert.FromBase64String(network.DataSecret), Encoding.UTF8.GetBytes(groupId)));
}


public sealed class PlatformNode
{
    public string Id { get; set; } = Secrets.Id();
    public string Name { get; set; } = "";
    public string Role { get; set; } = "";
    public string Endpoint { get; set; } = "";
    public string TokenHash { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public DateTimeOffset? LastSeenAt { get; set; }
    public string Version { get; set; } = "";
    public string[] OnlineDeviceIds { get; set; } = [];
}
public sealed record PasswordRequest(string CurrentPassword, string NewPassword);
public sealed record RecoveryRequest(string Email, string RecoveryCode, string NewPassword);
public sealed record NodeRequest(string Name, string Role, string Endpoint);
public sealed record NodeHeartbeatRequest(string NodeId, string Role, string Version, string[]? DeviceIds = null);

public sealed class MailSettings
{
    public bool Enabled { get; set; }
    public string Host { get; set; } = "";
    public int Port { get; set; } = 465;
    public string Security { get; set; } = "ssl";
    public string Username { get; set; } = "";
    public string PasswordCiphertext { get; set; } = "";
    public string FromEmail { get; set; } = "";
    public string FromName { get; set; } = "P2P VPN";
    public string NotificationEmail { get; set; } = "";
    public bool NotifyRegistrations { get; set; } = true;
    public bool NotifyMembershipChanges { get; set; } = true;
    public DateTimeOffset? LastSentAt { get; set; }
    public DateTimeOffset? LastTestAt { get; set; }
    public string LastError { get; set; } = "";
}
public sealed class EmailChallenge
{
    public string Id { get; set; } = Secrets.Id();
    public string Email { get; set; } = "";
    public string CodeHash { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset ExpiresAt { get; set; }
    public int Attempts { get; set; }
    public bool Ready { get; set; }
    public bool Used { get; set; }
}
public sealed record EmailRequest(string Email);
public sealed record DisabledRequest(bool Disabled);
public sealed record MailSettingsRequest(bool Enabled, string Host, int Port, string Security, string Username,
    string? Password, string FromEmail, string FromName, string NotificationEmail,
    bool NotifyRegistrations = true, bool NotifyMembershipChanges = true);

public sealed class InstallTicket
{
    public string Id { get; set; } = Secrets.Id();
    public string NetworkId { get; set; } = "";
    public string GroupId { get; set; } = "";
    public string Name { get; set; } = "";
    public string Platform { get; set; } = "";
    public string Hash { get; set; } = "";
    public DateTimeOffset ExpiresAt { get; set; }
    public bool Revoked { get; set; }
    public string? ClaimHash { get; set; }
    public string? DeviceId { get; set; }
}
public sealed record InstallRequest(string Name, string GroupId, string Platform);
public sealed record InstallClaimRequest(string Claim, string Platform);
