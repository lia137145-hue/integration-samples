using System.Diagnostics;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Diadoc.Api;
using Diadoc.Api.Cryptography;
using Duende.IdentityModel.Client;

var clientId = "ci_SMS-IT";
var clientSecret = "3240955a-e94f-18de-07b5-393008d35a4a"; // лучше не хранить в коде

var httpClient = new HttpClient();

var deviceAuthorizationResponse = await httpClient.RequestDeviceAuthorizationAsync(new DeviceAuthorizationRequest
{
    Address = "https://identity.kontur.ru/connect/deviceauthorization",
    Scope = "openid profile email offline_access Diadoc.PublicAPI",
    ClientId = clientId,
    ClientSecret = clientSecret
});

if (deviceAuthorizationResponse.IsError)
    throw new Exception(deviceAuthorizationResponse.Error);

Console.WriteLine($"Url for user authorization: {deviceAuthorizationResponse.VerificationUriComplete}");
OpenBrowser(deviceAuthorizationResponse.VerificationUriComplete!);

var accessToken = await PollAccessToken();

var diadoc = new DiadocApi(clientId, "https://diadoc-api.kontur.ru", new WinApiCrypt());
diadoc.UseOidc();

var organizations = diadoc.GetMyOrganizations(accessToken);

// 1) Берем нужную организацию
var org = organizations.Organizations
    .FirstOrDefault(x => x.FullName == "Тестовая организация №9615332")
    ?? throw new Exception("Организация не найдена");

// Для HTTP-методов удобнее GUID без @diadoc.ru
var boxId = org.Boxes.First().BoxIdGuid;
Console.WriteLine($"BoxIdGuid: {boxId}");

// 2) Находим сотрудника
var employee = await FindEmployeeByEmailAsync(httpClient, accessToken, boxId, "ivan.lipatov@sms-a.ru");
//var employee = await FindEmployeeByEmailAsync(httpClient, accessToken, boxId, "aleksandr.bomm@sms-a.ru");
Console.WriteLine($"UserId сотрудника: {employee.UserId}, DepartmentId: {employee.DepartmentId}");

// 3) Определяем подразделения
// Для примера отправляем из головного подразделения
var fromDepartmentId = "00000000-0000-0000-0000-000000000000";
var toDepartmentId = string.IsNullOrWhiteSpace(employee.DepartmentId)
    ? "00000000-0000-0000-0000-000000000000"
    : employee.DepartmentId;

// 4) Готовим файл и подпись отправителя
var filePath = @"C:\Temp\document.pdf";
//var sigPath = @"C:\Temp\document.pdf.sig"; // подпись отправителя
var documentBytes = await File.ReadAllBytesAsync(filePath);
//var signatureBytes = await File.ReadAllBytesAsync(sigPath);

// 5) Создаем внутреннее сообщение с документом
var createResult = await CreateInternalMessageAsync(
    httpClient,
    accessToken,
    boxId,
    fromDepartmentId,
    toDepartmentId,
    documentBytes,
    //signatureBytes,
    Path.GetFileName(filePath)
);

Console.WriteLine($"MessageId: {createResult.MessageId}");
Console.WriteLine($"InitialDocumentId: {createResult.EntityId}");

// 6) Отправляем запрос подписи сотруднику
await SendSignatureRequestAsync(
    httpClient,
    accessToken,
    boxId,
    createResult.MessageId,
    createResult.EntityId,
    employee.UserId,
    "Подпишите документ"
);

Console.WriteLine("Запрос подписи отправлен");

static void OpenBrowser(string url)
{
    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
    {
        Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true });
    }
    else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
    {
        Process.Start("xdg-open", url);
    }
    else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
    {
        Process.Start("open", url);
    }
}

async Task<string> PollAccessToken()
{
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(deviceAuthorizationResponse.ExpiresIn!.Value));

    while (!cts.IsCancellationRequested)
    {
        var tokenResponse = await httpClient.RequestDeviceTokenAsync(new DeviceTokenRequest
        {
            Address = "https://identity.kontur.ru/connect/token",
            DeviceCode = deviceAuthorizationResponse.DeviceCode!,
            ClientId = clientId,
            ClientSecret = clientSecret
        });

        if (tokenResponse.Error is "authorization_pending" or "slow_down")
        {
            await Task.Delay(TimeSpan.FromSeconds(deviceAuthorizationResponse.Interval));
            continue;
        }

        if (tokenResponse.IsError)
            throw new Exception(tokenResponse.Error);

        return tokenResponse.AccessToken!;
    }

    throw new Exception("Device code expired");
}

async Task<(string UserId, string? DepartmentId)> FindEmployeeByEmailAsync(
    HttpClient httpClient,
    string accessToken,
    string boxId,
    string email)
{
    for (var page = 1; page <= 20; page++)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"https://diadoc-api.kontur.ru/GetEmployees?boxId={Uri.EscapeDataString(boxId)}&page={page}&count=50");

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
		request.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

        using var response = await httpClient.SendAsync(request);
        var json = await response.Content.ReadAsStringAsync();
        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(json);

        var employees = doc.RootElement.GetProperty("Employees");
        if (employees.GetArrayLength() == 0)
            break;

        foreach (var employee in employees.EnumerateArray())
        {
            if (!employee.TryGetProperty("User", out var user))
                continue;

            var login = user.TryGetProperty("Login", out var loginProp) ? loginProp.GetString() : null;
            if (!string.Equals(login, email, StringComparison.OrdinalIgnoreCase))
                continue;

            var userId = user.GetProperty("UserId").GetString()
                         ?? throw new Exception("UserId пустой");

            string? departmentId = null;
            if (employee.TryGetProperty("Permissions", out var perms) &&
                perms.TryGetProperty("UserDepartmentId", out var depProp))
            {
                departmentId = depProp.GetString();
            }

            return (userId, departmentId);
        }
    }

    throw new Exception($"Сотрудник {email} не найден");
}

async Task<(string MessageId, string EntityId)> CreateInternalMessageAsync(
    HttpClient httpClient,
    string accessToken,
    string boxId,
    string fromDepartmentId,
    string toDepartmentId,
    byte[] documentBytes,
    //byte[] signatureBytes,
    string fileName)
{
    var payload = new
    {
        FromBoxId = boxId,
        IsInternal = true,
        FromDepartmentId = fromDepartmentId,
        ToDepartmentId = toDepartmentId,
        DocumentAttachments = new[]
        {
            new
            {
                SignedContent = new
                {
                    Content = Convert.ToBase64String(documentBytes),
					SignWithTestSignature = true
                    //Signature = Convert.ToBase64String(signatureBytes)
                },
                TypeNamedId = "Nonformalized",
                Metadata = new[]
                {
                    new { Key = "FileName", Value = fileName }
                }
            }
        }
    };

    var json = JsonSerializer.Serialize(payload);

    using var request = new HttpRequestMessage(
        HttpMethod.Post,
        "https://diadoc-api.kontur.ru/V3/PostMessage");

    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
    request.Content = new StringContent(json, Encoding.UTF8, "application/json");

    using var response = await httpClient.SendAsync(request);
    var responseBody = await response.Content.ReadAsStringAsync();
    //response.EnsureSuccessStatusCode();
	if (!response.IsSuccessStatusCode)
	{
		throw new Exception(
			$"PostMessage failed: {(int)response.StatusCode} {response.ReasonPhrase}\n{responseBody}");
	}

    using var doc = JsonDocument.Parse(responseBody);

    var messageId = doc.RootElement.GetProperty("MessageId").GetString()
                   ?? throw new Exception("В ответе нет MessageId");

    var entities = doc.RootElement.GetProperty("Entities");
    foreach (var entity in entities.EnumerateArray())
    {
        if (entity.TryGetProperty("EntityType", out var entityType) &&
            entityType.GetString() == "Attachment")
        {
            var entityId = entity.GetProperty("EntityId").GetString()
                           ?? throw new Exception("EntityId пустой");

            return (messageId, entityId);
        }
    }

    throw new Exception("Не найден Attachment/EntityId в ответе PostMessage");
}

async Task SendSignatureRequestAsync(
    HttpClient httpClient,
    string accessToken,
    string boxId,
    string messageId,
    string initialDocumentId,
    string targetUserId,
    string comment)
{
    var payload = new
    {
        BoxId = boxId,
        MessageId = messageId,
        ResolutionRequests = new[]
        {
            new
            {
                InitialDocumentId = initialDocumentId,
                Type = "SignatureRequest",
                TargetUserId = targetUserId,
                Comment = comment
            }
        }
    };

    var json = JsonSerializer.Serialize(payload);

    using var request = new HttpRequestMessage(
        HttpMethod.Post,
        "https://diadoc-api.kontur.ru/V4/PostMessagePatch");

    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
    request.Content = new StringContent(json, Encoding.UTF8, "application/json");

    using var response = await httpClient.SendAsync(request);
    var responseBody = await response.Content.ReadAsStringAsync();

    if (!response.IsSuccessStatusCode)
        throw new Exception($"PostMessagePatch failed: {(int)response.StatusCode} {response.ReasonPhrase}\n{responseBody}");
}