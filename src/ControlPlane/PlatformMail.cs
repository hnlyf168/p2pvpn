using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EdgeVpn;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
namespace EdgeVpn.ControlPlane;
public sealed class PlatformMail(StateStore store, IConfiguration config, IHostEnvironment environment, ILogger<PlatformMail> logger)
{
    private readonly SemaphoreSlim sending = new(4);
    private string? Pickup => environment.IsDevelopment() ? config["Mail:PickupDirectory"] : null;
    private byte[] Key => SHA256.HashData(Encoding.UTF8.GetBytes("edge-vpn-mail-v1:" + config["AdminKey"]));
    public bool Ready => Pickup is not null || store.Read(db => db.Mail.Enabled && db.Mail.Host.Length > 0 && db.Mail.FromEmail.Length > 0);
    public object PublicSettings() => store.Read(db => new { db.Mail.Enabled, db.Mail.Host, db.Mail.Port, db.Mail.Security, db.Mail.Username,
        passwordConfigured = db.Mail.PasswordCiphertext.Length > 0, db.Mail.FromEmail, db.Mail.FromName, db.Mail.NotificationEmail,
        db.Mail.NotifyRegistrations, db.Mail.NotifyMembershipChanges, db.Mail.LastSentAt, db.Mail.LastTestAt, db.Mail.LastError });
    public string Protect(string text)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(12), plain = Encoding.UTF8.GetBytes(text), cipher = new byte[plain.Length], tag = new byte[16];
        using var aes = new AesGcm(Key, 16); aes.Encrypt(nonce, plain, cipher, tag);
        return Convert.ToBase64String(nonce.Concat(tag).Concat(cipher).ToArray());
    }
    private string Unprotect(string value)
    {
        if (value.Length == 0) return "";
        var data = Convert.FromBase64String(value); var plain = new byte[data.Length - 28];
        using var aes = new AesGcm(Key, 16); aes.Decrypt(data.AsSpan(0,12), data.AsSpan(28), data.AsSpan(12,16), plain);
        return Encoding.UTF8.GetString(plain);
    }
    public async Task Send(string to, string subject, string body, CancellationToken ct)
    {
        if (!Ready) throw new InvalidOperationException("注册邮件服务尚未启用，请联系平台管理员配置发信邮箱。");
        await sending.WaitAsync(ct);
        try
        {
            if (Pickup is { } pickup)
            {
                Directory.CreateDirectory(pickup);
                await File.WriteAllTextAsync(Path.Combine(pickup, Guid.NewGuid().ToString("N") + ".json"), JsonSerializer.Serialize(new { To = to, Subject = subject, Body = body }), ct);
            }
            else
            {
                var settings = store.Read(db => db.Mail);
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(20));
                using var smtp = new SmtpClient { Timeout = 20000 };
                await smtp.ConnectAsync(settings.Host, settings.Port, settings.Security == "ssl" ? SecureSocketOptions.SslOnConnect : SecureSocketOptions.StartTls, deadline.Token);
                if (settings.Username.Length > 0) await smtp.AuthenticateAsync(settings.Username, Unprotect(settings.PasswordCiphertext), deadline.Token);
                var message = new MimeMessage();
                message.From.Add(new MailboxAddress(settings.FromName, settings.FromEmail)); message.To.Add(MailboxAddress.Parse(to));
                message.Subject = subject; message.Body = new TextPart("plain") { Text = body };
                await smtp.SendAsync(message, deadline.Token); await smtp.DisconnectAsync(true, deadline.Token);
            }
            store.Write(db => { db.Mail.LastSentAt = DateTimeOffset.UtcNow; db.Mail.LastError = ""; return 0; });
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            logger.LogWarning("Email delivery failed: {Type}", ex.GetType().Name);
            store.Write(db => { db.Mail.LastError = "邮件发送失败，请检查 SMTP 连接、证书、账号和授权码。"; return 0; });
            throw new InvalidOperationException("邮件未发送成功，请联系管理员检查发信配置，稍后重试。");
        }
        finally { sending.Release(); }
    }
    public async Task Notify(string subject, string body, bool membership = false)
    {
        var settings = store.Read(db => db.Mail);
        if (!Ready || settings.NotificationEmail.Length == 0 || !(membership ? settings.NotifyMembershipChanges : settings.NotifyRegistrations)) return;
        try { await Send(settings.NotificationEmail, subject, body, CancellationToken.None); }
        catch (Exception ex) { logger.LogWarning("Notification delivery failed: {Type}", ex.GetType().Name); }
    }
}
