using System.Net.Http.Headers;
using System.Text.Encodings.Web;
using System.Text;
using System.Text.Json;
using DiadocHttpClientException = Diadoc.Api.Http.HttpClientException;
using Diadoc.Api;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace SampleWebApp.Oidc.Pages;

[Authorize]
public class IndexModel : PageModel
{
    private const string RootDepartmentId = "00000000-0000-0000-0000-000000000000";
    private static readonly JsonSerializerOptions DisplayJsonOptions = new(JsonSerializerOptions.Default)
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private readonly ILogger<IndexModel> _logger;
    private readonly IDiadocApi _diadocApi;
    private readonly IHttpClientFactory _httpClientFactory;

    public IndexModel(ILogger<IndexModel> logger, IDiadocApi diadocApi, IHttpClientFactory httpClientFactory)
    {
        _logger = logger;
        _diadocApi = diadocApi;
        _httpClientFactory = httpClientFactory;
    }

    [BindProperty]
    public SignatureRequestForm Input { get; set; } = new();

    [BindProperty]
    public DownloadDocumentForm DownloadInput { get; set; } = new();

    public string? UserName { get; private set; }
    public string? UserLogin { get; private set; }
    public string? DiadocRequest { get; private set; }
    public string? DiadocResponse { get; private set; }
    public string? OperationResult { get; private set; }
    public string? RouteDiagnostics { get; private set; }
    public List<SelectListItem> AvailableOrganizations { get; private set; } = new();
    public List<SelectListItem> AvailableDepartments { get; private set; } = new();

    public async Task<IActionResult> OnGet()
    {
        try
        {
            await LoadPageAsync();
            return Page();
        }
        catch (DiadocHttpClientException ex) when (IsInvalidAuthToken(ex))
        {
            _logger.LogWarning(ex, "Токен Диадока недействителен, запускаю повторную авторизацию.");
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Challenge(
                new AuthenticationProperties { RedirectUri = Url.Page("/Index") ?? "/" },
                OpenIdConnectDefaults.AuthenticationScheme);
        }
    }

    public async Task<IActionResult> OnPostSendForSignatureAsync()
    {
        await LoadPageAsync();

        if (Input.Document is null || Input.Document.Length == 0)
            ModelState.AddModelError($"{nameof(Input)}.{nameof(Input.Document)}", "Выберите файл документа.");

        if (string.IsNullOrWhiteSpace(Input.InternalRecipientLoginOrUserId))
        {
            ModelState.AddModelError(
                $"{nameof(Input)}.{nameof(Input.InternalRecipientLoginOrUserId)}",
                "Укажите логин или UserId получателя внутреннего сообщения.");
        }

        if (!ModelState.IsValid)
            return Page();

        try
        {
            var accessToken = await HttpContext.GetTokenAsync("access_token");
            if (string.IsNullOrWhiteSpace(accessToken))
                throw new InvalidOperationException("Не удалось получить access token.");

            var requestedBoxId = string.IsNullOrWhiteSpace(Input.OrganizationBoxId)
                ? Input.BoxId
                : Input.OrganizationBoxId;
            var boxId = await ResolveBoxIdAsync(accessToken, requestedBoxId);
            Input.BoxId = boxId;
            Input.OrganizationBoxId = boxId;

            var httpClient = _httpClientFactory.CreateClient();
            var currentUserLogin = ResolveCurrentUserLogin();

            await using var documentStream = Input.Document!.OpenReadStream();
            using var memoryStream = new MemoryStream();
            await documentStream.CopyToAsync(memoryStream);
            var documentBytes = memoryStream.ToArray();

            var internalRecipient = await ResolveInternalRecipientAsync(
                httpClient,
                accessToken,
                boxId,
                Input.InternalRecipientLoginOrUserId!,
                Input.InternalRecipientDepartmentId);

            var signatureRecipientLookup = string.IsNullOrWhiteSpace(Input.SignatureRecipientLoginOrUserId)
                ? Input.InternalRecipientLoginOrUserId!
                : Input.SignatureRecipientLoginOrUserId!;

            EmployeeInfo? signatureRecipient = null;
            string? signatureRequestSkippedReason = null;

            try
            {
                signatureRecipient = await ResolveSignatureRecipientAsync(
                    httpClient,
                    accessToken,
                    boxId,
                    signatureRecipientLookup,
                    Input.InternalRecipientDepartmentId);
            }
            catch (InvalidOperationException ex) when (!Guid.TryParse(signatureRecipientLookup, out _))
            {
                signatureRequestSkippedReason =
                    "Запрос подписи не отправлен автоматически: для подписанта известен только email/логин, а доступ к GetEmployees запрещен. Диадок в этом случае требует UserId.";
                _logger.LogWarning(ex, "Не удалось определить UserId подписанта по email/логину, запрос подписи будет пропущен.");
            }

            var organizations = await _diadocApi.GetMyOrganizationsAsync(accessToken);
            var selectedOrganization = GetOrganizationByBoxId(organizations, boxId);
            var departments = GetDepartmentsFromOrganizations(organizations, boxId);
            var route = BuildInternalMessageRoute(internalRecipient, departments, Input.FromDepartmentId);
            var useTestSignature = selectedOrganization?.IsTest == true;
            var postMessagePatchApplied = false;
            RouteDiagnostics = JsonSerializer.Serialize(new
                {
                    OrganizationBoxId = boxId,
                    OrganizationIsTest = selectedOrganization?.IsTest,
                    PostMessageSignWithTestSignature = useTestSignature,
                    PostMessageNeedRecipientSignature = true,
                    PostMessagePatchApplied = postMessagePatchApplied,
                    SelectedFromDepartmentId = Input.FromDepartmentId,
                    SelectedRecipientDepartmentId = Input.InternalRecipientDepartmentId,
                    InternalRecipient = new
                    {
                        internalRecipient.UserId,
                        internalRecipient.Login,
                        DepartmentId = NormalizeDepartmentId(internalRecipient.DepartmentId)
                    },
                    SignatureRecipient = new
                    {
                        UserId = signatureRecipient?.UserId,
                        Login = signatureRecipient?.Login,
                        DepartmentId = signatureRecipient is null
                            ? null
                            : NormalizeDepartmentId(signatureRecipient.DepartmentId)
                    },
                    SignatureRequestSkippedReason = signatureRequestSkippedReason,
                    Route = new
                    {
                        route.FromDepartmentId,
                        route.ToDepartmentId,
                        route.FromDepartmentName,
                        route.ToDepartmentName
                    }
                },
                DisplayJsonOptions);

            var createdMessage = await CreateInternalMessageAsync(
                httpClient,
                accessToken,
                boxId,
                route.FromDepartmentId,
                route.ToDepartmentId,
                documentBytes,
                useTestSignature,
                Input.Document.FileName);

            if (signatureRecipient is not null &&
                !string.IsNullOrWhiteSpace(currentUserLogin) &&
                string.Equals(signatureRecipient.Login, currentUserLogin, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Подписант не должен совпадать с текущим пользователем.");
            }

            if (signatureRecipient is not null && !string.IsNullOrWhiteSpace(signatureRecipient.UserId))
            {
                try
                {
                    await SendSignatureRequestAsync(
                        httpClient,
                        accessToken,
                        boxId,
                        createdMessage.MessageId,
                        createdMessage.EntityId,
                        signatureRecipient.UserId,
                        string.IsNullOrWhiteSpace(Input.Comment) ? "Подпишите документ" : Input.Comment!);
                    postMessagePatchApplied = true;
                }
                catch (InvalidOperationException ex) when (IsPostMessagePatchStateConflict(ex))
                {
                    signatureRequestSkippedReason =
                        "Документ отправлен, подпись запрошена через NeedRecipientSignature. Дополнительный PostMessagePatch пока недоступен (409) и будет пропущен.";
                    _logger.LogWarning(ex,
                        "Документ создан, но PostMessagePatch недоступен из-за состояния документа. MessageId={MessageId}, EntityId={EntityId}",
                        createdMessage.MessageId,
                        createdMessage.EntityId);
                }
            }

            DownloadInput.BoxId = boxId;
            DownloadInput.MessageId = createdMessage.MessageId;
            DownloadInput.EntityId = createdMessage.EntityId;

            RouteDiagnostics = JsonSerializer.Serialize(new
                {
                    OrganizationBoxId = boxId,
                    OrganizationIsTest = selectedOrganization?.IsTest,
                    PostMessageSignWithTestSignature = useTestSignature,
                    PostMessageNeedRecipientSignature = true,
                    PostMessagePatchApplied = postMessagePatchApplied,
                    SelectedFromDepartmentId = Input.FromDepartmentId,
                    SelectedRecipientDepartmentId = Input.InternalRecipientDepartmentId,
                    InternalRecipient = new
                    {
                        internalRecipient.UserId,
                        internalRecipient.Login,
                        DepartmentId = NormalizeDepartmentId(internalRecipient.DepartmentId)
                    },
                    SignatureRecipient = new
                    {
                        UserId = signatureRecipient?.UserId,
                        Login = signatureRecipient?.Login,
                        DepartmentId = signatureRecipient is null
                            ? null
                            : NormalizeDepartmentId(signatureRecipient.DepartmentId)
                    },
                    SignatureRequestSkippedReason = signatureRequestSkippedReason,
                    Route = new
                    {
                        route.FromDepartmentId,
                        route.ToDepartmentId,
                        route.FromDepartmentName,
                        route.ToDepartmentName
                    }
                },
                DisplayJsonOptions);

            OperationResult = JsonSerializer.Serialize(new
                {
                    BoxId = boxId,
                    PostMessageSignWithTestSignature = useTestSignature,
                    PostMessageNeedRecipientSignature = true,
                    PostMessagePatchApplied = postMessagePatchApplied,
                    InternalRecipient = new
                    {
                        internalRecipient.UserId,
                        internalRecipient.Login,
                        DepartmentId = NormalizeDepartmentId(internalRecipient.DepartmentId)
                    },
                    SignatureRecipient = new
                    {
                        UserId = signatureRecipient?.UserId,
                        Login = signatureRecipient?.Login,
                        DepartmentId = signatureRecipient is null
                            ? null
                            : NormalizeDepartmentId(signatureRecipient.DepartmentId)
                    },
                    SignatureRequestSkippedReason = signatureRequestSkippedReason,
                    createdMessage.MessageId,
                    InitialDocumentId = createdMessage.EntityId,
                    Route = new
                    {
                        route.FromDepartmentId,
                        route.ToDepartmentId,
                        route.FromDepartmentName,
                        route.ToDepartmentName
                    }
                },
                DisplayJsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка отправки документа на подпись");
            ModelState.AddModelError(string.Empty, ex.Message);
        }

        return Page();
    }

    public async Task<IActionResult> OnPostRefreshOrganizationAsync()
    {
        await LoadPageAsync();
        ModelState.Clear();
        return Page();
    }

    public async Task<IActionResult> OnPostDownloadSignedDocumentAsync()
    {
        await LoadPageAsync();

        if (string.IsNullOrWhiteSpace(DownloadInput.BoxId))
            ModelState.AddModelError($"{nameof(DownloadInput)}.{nameof(DownloadInput.BoxId)}", "Укажите BoxId.");
        if (string.IsNullOrWhiteSpace(DownloadInput.MessageId))
            ModelState.AddModelError($"{nameof(DownloadInput)}.{nameof(DownloadInput.MessageId)}", "Укажите MessageId.");
        if (string.IsNullOrWhiteSpace(DownloadInput.EntityId))
            ModelState.AddModelError($"{nameof(DownloadInput)}.{nameof(DownloadInput.EntityId)}", "Укажите EntityId документа.");

        if (!ModelState.IsValid)
            return Page();

        try
        {
            var accessToken = await HttpContext.GetTokenAsync("access_token");
            if (string.IsNullOrWhiteSpace(accessToken))
                throw new InvalidOperationException("Не удалось получить access token.");

            var downloadMode = ParseDownloadMode(DownloadInput.Mode);
            var documentInfo = await GetDocumentDownloadInfoAsync(
                accessToken,
                DownloadInput.BoxId!,
                DownloadInput.MessageId!,
                DownloadInput.EntityId!);

            return downloadMode switch
            {
                DownloadMode.Document => File(
                    documentInfo.DocumentContent,
                    "application/octet-stream",
                    documentInfo.OriginalDownloadFileName),
                DownloadMode.Signature => File(
                    documentInfo.SignatureContent ?? throw new InvalidOperationException("Подпись для документа не найдена."),
                    "application/octet-stream",
                    documentInfo.SignatureFileName),
                DownloadMode.SeparateArchive => File(
                    CreateSeparateFilesArchive(documentInfo),
                    "application/zip",
                    documentInfo.SeparateArchiveFileName),
                _ => await CreateEmbeddedSignatureArchiveResultAsync(
                    accessToken,
                    DownloadInput.BoxId!,
                    DownloadInput.MessageId!,
                    DownloadInput.EntityId!,
                    documentInfo.EmbeddedArchiveFileName)
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка скачивания подписанного документа");
            ModelState.AddModelError(string.Empty, ex.Message);
            return Page();
        }
    }

    public Task<IActionResult> OnPostDownloadOriginalAsync() =>
        HandleDownloadAsync(async (accessToken, request) =>
        {
            var documentInfo = await GetDocumentDownloadInfoAsync(accessToken, request.BoxId, request.MessageId, request.EntityId);
            return File(documentInfo.DocumentContent, "application/octet-stream", documentInfo.OriginalDownloadFileName);
        });

    public Task<IActionResult> OnPostDownloadSignedPdfAsync() =>
        HandleDownloadAsync(async (accessToken, request) =>
        {
            var documentInfo = await GetDocumentDownloadInfoAsync(accessToken, request.BoxId, request.MessageId, request.EntityId);
            var printForm = await WaitForPrintFormAsync(accessToken, request.BoxId, request.MessageId, request.EntityId);
            if (!printForm.HasContent || printForm.Content?.Bytes is null || printForm.Content.Bytes.Length == 0)
                throw new InvalidOperationException("Diadoc не вернул PDF-представление документа.");

            var fileName = string.IsNullOrWhiteSpace(printForm.Content.FileName)
                ? documentInfo.SignedPdfFileName
                : BuildFriendlySignedPdfFileName(printForm.Content.FileName, documentInfo.DocumentFileName);
            var contentType = string.IsNullOrWhiteSpace(printForm.Content.ContentType)
                ? "application/pdf"
                : printForm.Content.ContentType;

            return File(printForm.Content.Bytes, contentType, fileName);
        });

    public Task<IActionResult> OnPostDownloadDocflowAsync() =>
        HandleDownloadAsync(async (accessToken, request) =>
        {
            var documentInfo = await GetDocumentDownloadInfoAsync(accessToken, request.BoxId, request.MessageId, request.EntityId);
            return await CreateDocflowArchiveResultAsync(
                accessToken,
                request.BoxId,
                request.MessageId,
                request.EntityId,
                documentInfo.DocflowArchiveFileName);
        });

    public Task<IActionResult> OnPostDownloadSignatureAsync() =>
        HandleDownloadAsync(async (accessToken, request) =>
        {
            var documentInfo = await GetDocumentDownloadInfoAsync(accessToken, request.BoxId, request.MessageId, request.EntityId);
            return File(
                documentInfo.SignatureContent ?? throw new InvalidOperationException("Подпись для документа не найдена."),
                "application/octet-stream",
                documentInfo.SignatureFileName);
        });

    private async Task LoadPageAsync()
    {
        UserName = User.FindFirst("name")?.Value ?? User.Identity?.Name ?? "пользователь";
        UserLogin = ResolveCurrentUserLogin();
        DiadocRequest = "/GetMyOrganizations";

        var accessToken = await HttpContext.GetTokenAsync("access_token");
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            DiadocResponse = "Access token отсутствует.";
            return;
        }

        var organizations = await _diadocApi.GetMyOrganizationsAsync(accessToken);
        DiadocResponse = JsonSerializer.Serialize(organizations, DisplayJsonOptions);

        AvailableOrganizations = organizations.Organizations
            .SelectMany(org => org.Boxes.Select(box => new SelectListItem(
                $"{(string.IsNullOrWhiteSpace(org.ShortName) ? org.FullName : org.ShortName)} ({box.BoxIdGuid})",
                box.BoxIdGuid,
                string.Equals(box.BoxIdGuid, Input.OrganizationBoxId, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(box.BoxIdGuid, Input.BoxId, StringComparison.OrdinalIgnoreCase))))
            .ToList();

        if (string.IsNullOrWhiteSpace(Input.OrganizationBoxId))
        {
            Input.OrganizationBoxId = organizations.Organizations
                .SelectMany(x => x.Boxes)
                .Select(x => x.BoxIdGuid)
                .FirstOrDefault();
        }

        if (string.IsNullOrWhiteSpace(Input.BoxId))
        {
            Input.BoxId = Input.OrganizationBoxId;
        }

        if (!string.IsNullOrWhiteSpace(Input.OrganizationBoxId))
            Input.BoxId = Input.OrganizationBoxId;

        if (string.IsNullOrWhiteSpace(DownloadInput.BoxId))
            DownloadInput.BoxId = Input.BoxId;

        if (!string.IsNullOrWhiteSpace(Input.BoxId))
        {
            try
            {
                var departments = GetDepartmentsFromOrganizations(organizations, Input.BoxId);
                AvailableDepartments = departments
                    .Select(x => new SelectListItem(
                        $"{x.DepartmentName} ({x.DepartmentId})",
                        x.DepartmentId,
                        string.Equals(x.DepartmentId, Input.FromDepartmentId, StringComparison.OrdinalIgnoreCase)))
                    .ToList();

                if (string.IsNullOrWhiteSpace(Input.FromDepartmentId))
                {
                    Input.FromDepartmentId = departments
                        .FirstOrDefault(x =>
                            string.Equals(x.DepartmentName, "Тестирование", StringComparison.OrdinalIgnoreCase))
                        ?.DepartmentId;
                }

                if (string.IsNullOrWhiteSpace(Input.InternalRecipientDepartmentId))
                    Input.InternalRecipientDepartmentId = Input.FromDepartmentId;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Не удалось загрузить список подразделений для формы.");
            }
        }
    }

    private static bool IsInvalidAuthToken(DiadocHttpClientException exception)
    {
        return exception.ResponseStatusCode == System.Net.HttpStatusCode.Unauthorized ||
               string.Equals(exception.DiadocErrorCode, "Http.Auth", StringComparison.OrdinalIgnoreCase);
    }

    private async Task<string> ResolveBoxIdAsync(string accessToken, string? requestedBoxId)
    {
        if (!string.IsNullOrWhiteSpace(requestedBoxId))
            return requestedBoxId;

        var organizations = await _diadocApi.GetMyOrganizationsAsync(accessToken);
        var boxId = organizations.Organizations
            .SelectMany(x => x.Boxes)
            .Select(x => x.BoxIdGuid)
            .FirstOrDefault();

        if (string.IsNullOrWhiteSpace(boxId))
            throw new InvalidOperationException("Не удалось определить BoxId из GetMyOrganizations.");

        return boxId;
    }

    private string? ResolveCurrentUserLogin()
    {
        return User.FindFirst("email")?.Value
               ?? User.FindFirst("preferred_username")?.Value
               ?? User.Identity?.Name;
    }

    private static string NormalizeDepartmentId(string? departmentId)
    {
        return string.IsNullOrWhiteSpace(departmentId) ? RootDepartmentId : departmentId;
    }

    private async Task<EmployeeInfo> FindEmployeeByLoginOrUserIdAsync(
        HttpClient httpClient,
        string accessToken,
        string boxId,
        string loginOrUserId,
        string? manualDepartmentId)
    {
        var employees = await GetEmployeesAsync(httpClient, accessToken, boxId);
        var employee = employees.FirstOrDefault(x =>
            string.Equals(x.UserId, loginOrUserId, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(x.Login, loginOrUserId, StringComparison.OrdinalIgnoreCase));

        if (employee is null)
            throw new InvalidOperationException($"Сотрудник '{loginOrUserId}' не найден в ящике {boxId}.");

        return employee;
    }

    private async Task<EmployeeInfo> ResolveEmployeeWithFallbackAsync(
        HttpClient httpClient,
        string accessToken,
        string boxId,
        string loginOrUserId,
        string? manualDepartmentId)
    {
        try
        {
            return await FindEmployeeByLoginOrUserIdAsync(
                httpClient,
                accessToken,
                boxId,
                loginOrUserId,
                manualDepartmentId);
        }
        catch (HttpRequestException ex) when (
            ex.StatusCode == System.Net.HttpStatusCode.Forbidden &&
            Guid.TryParse(loginOrUserId, out _) &&
            !string.IsNullOrWhiteSpace(manualDepartmentId))
        {
            _logger.LogInformation(
                "GetEmployees вернул 403, использую вручную указанные UserId и DepartmentId.");
            return new EmployeeInfo(loginOrUserId, manualDepartmentId, null);
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            throw new InvalidOperationException(
                "Нет доступа к GetEmployees. Укажите получателя по UserId и выберите его подразделение вручную.",
                ex);
        }
    }

    private async Task<EmployeeInfo> ResolveInternalRecipientAsync(
        HttpClient httpClient,
        string accessToken,
        string boxId,
        string loginOrUserId,
        string? manualDepartmentId)
    {
        try
        {
            return await FindEmployeeByLoginOrUserIdAsync(
                httpClient,
                accessToken,
                boxId,
                loginOrUserId,
                manualDepartmentId);
        }
        catch (HttpRequestException ex) when (
            ex.StatusCode == System.Net.HttpStatusCode.Forbidden &&
            !string.IsNullOrWhiteSpace(manualDepartmentId))
        {
            _logger.LogInformation(
                "GetEmployees вернул 403, для получателя внутреннего сообщения использую вручную выбранное подразделение.");
            return new EmployeeInfo(
                Guid.TryParse(loginOrUserId, out _) ? loginOrUserId : string.Empty,
                manualDepartmentId,
                loginOrUserId);
        }
    }

    private async Task<EmployeeInfo> ResolveSignatureRecipientAsync(
        HttpClient httpClient,
        string accessToken,
        string boxId,
        string loginOrUserId,
        string? manualDepartmentId)
    {
        try
        {
            return await ResolveEmployeeWithFallbackAsync(
                httpClient,
                accessToken,
                boxId,
                loginOrUserId,
                manualDepartmentId);
        }
        catch (InvalidOperationException ex) when (!Guid.TryParse(loginOrUserId, out _))
        {
            throw new InvalidOperationException(
                "Для подписанта при отсутствии доступа к GetEmployees нужно указать именно UserId, а не логин/email.",
                ex);
        }
    }

    private async Task<List<EmployeeInfo>> GetEmployeesAsync(
        HttpClient httpClient,
        string accessToken,
        string boxId)
    {
        var result = new List<EmployeeInfo>();

        for (var page = 1; page <= 20; page++)
        {
            using var request = new HttpRequestMessage(
                HttpMethod.Get,
                $"https://diadoc-api.kontur.ru/GetEmployees?boxId={Uri.EscapeDataString(boxId)}&page={page}&count=50");

            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

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

                var userId = user.GetProperty("UserId").GetString();
                if (string.IsNullOrWhiteSpace(userId))
                    continue;

                var login = user.TryGetProperty("Login", out var loginProp) ? loginProp.GetString() : null;
                string? departmentId = null;

                if (employee.TryGetProperty("Permissions", out var permissions) &&
                    permissions.TryGetProperty("UserDepartmentId", out var departmentProp))
                {
                    departmentId = departmentProp.GetString();
                }

                result.Add(new EmployeeInfo(userId, departmentId, login));
            }
        }

        return result;
    }

    private async Task<List<DepartmentInfo>> GetDepartmentsAsync(
        HttpClient httpClient,
        string accessToken,
        string boxId)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"https://diadoc-api.kontur.ru/admin/GetDepartments?boxId={Uri.EscapeDataString(boxId)}");

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        using var response = await httpClient.SendAsync(request);
        var json = await response.Content.ReadAsStringAsync();
        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(json);
        var result = new List<DepartmentInfo>();

        if (doc.RootElement.TryGetProperty("Departments", out var departments))
        {
            foreach (var department in departments.EnumerateArray())
            {
                var id = department.TryGetProperty("Id", out var idProp)
                    ? idProp.GetString()
                    : department.TryGetProperty("DepartmentId", out idProp)
                        ? idProp.GetString()
                        : null;

                if (string.IsNullOrWhiteSpace(id))
                    continue;

                var name = department.TryGetProperty("Name", out var nameProp) ? nameProp.GetString() : null;
                result.Add(new DepartmentInfo(id, string.IsNullOrWhiteSpace(name) ? id : name));
            }
        }

        if (result.All(x => !string.Equals(x.DepartmentId, RootDepartmentId, StringComparison.OrdinalIgnoreCase)))
            result.Insert(0, new DepartmentInfo(RootDepartmentId, "Головное подразделение"));

        return result;
    }

    private static List<DepartmentInfo> GetDepartmentsFromOrganizations(
        Diadoc.Api.Proto.OrganizationList organizationsResponse,
        string? boxId)
    {
        if (string.IsNullOrWhiteSpace(boxId))
            return new List<DepartmentInfo>();

        var selectedOrganization = organizationsResponse.Organizations.FirstOrDefault(org =>
            org.Boxes.Any(box => string.Equals(box.BoxIdGuid, boxId, StringComparison.OrdinalIgnoreCase)));

        var departments = selectedOrganization is null
            ? new List<DepartmentInfo>()
            : selectedOrganization.Departments
                .Select(x => new DepartmentInfo(
                    x.DepartmentId,
                    string.IsNullOrWhiteSpace(x.Name) ? x.DepartmentId : x.Name))
                .ToList();

        if (departments.All(x => !string.Equals(x.DepartmentId, RootDepartmentId, StringComparison.OrdinalIgnoreCase)))
            departments.Insert(0, new DepartmentInfo(RootDepartmentId, "Головное подразделение"));

        return departments;
    }

    private static Diadoc.Api.Proto.Organization? GetOrganizationByBoxId(
        Diadoc.Api.Proto.OrganizationList organizationsResponse,
        string? boxId)
    {
        if (string.IsNullOrWhiteSpace(boxId))
            return null;

        return organizationsResponse.Organizations.FirstOrDefault(org =>
            org.Boxes.Any(box => string.Equals(box.BoxIdGuid, boxId, StringComparison.OrdinalIgnoreCase)));
    }

    private static InternalMessageRoute BuildInternalMessageRoute(
        EmployeeInfo employee,
        List<DepartmentInfo> departments,
        string? preferredFromDepartmentId)
    {
        var toDepartmentId = NormalizeDepartmentId(employee.DepartmentId);
        var toDepartmentName = GetDepartmentName(departments, toDepartmentId);

        if (!string.IsNullOrWhiteSpace(preferredFromDepartmentId))
        {
            var fromDepartmentId = NormalizeDepartmentId(preferredFromDepartmentId);
            if (!string.Equals(fromDepartmentId, toDepartmentId, StringComparison.OrdinalIgnoreCase))
            {
                var fromDepartmentName = GetDepartmentName(departments, fromDepartmentId);

                return new InternalMessageRoute(
                    fromDepartmentId,
                    toDepartmentId,
                    fromDepartmentName,
                    toDepartmentName);
            }
        }

        if (!string.Equals(toDepartmentId, RootDepartmentId, StringComparison.OrdinalIgnoreCase))
        {
            return new InternalMessageRoute(
                RootDepartmentId,
                toDepartmentId,
                GetDepartmentName(departments, RootDepartmentId),
                toDepartmentName);
        }

        var alternateDepartment = departments.FirstOrDefault(x =>
            !string.Equals(x.DepartmentId, RootDepartmentId, StringComparison.OrdinalIgnoreCase));

        if (alternateDepartment is null)
        {
            throw new InvalidOperationException(
                "Не найдено другое подразделение для отправителя. Для внутреннего сообщения нужны разные FromDepartmentId и ToDepartmentId.");
        }

        return new InternalMessageRoute(
            alternateDepartment.DepartmentId,
            toDepartmentId,
            alternateDepartment.DepartmentName,
            toDepartmentName);
    }

    private static string GetDepartmentName(IEnumerable<DepartmentInfo> departments, string departmentId)
    {
        return departments.FirstOrDefault(x =>
                   string.Equals(x.DepartmentId, departmentId, StringComparison.OrdinalIgnoreCase))
               ?.DepartmentName
               ?? (string.Equals(departmentId, RootDepartmentId, StringComparison.OrdinalIgnoreCase)
                   ? "Головное подразделение"
                   : departmentId);
    }

    private async Task<MessageCreationResult> CreateInternalMessageAsync(
        HttpClient httpClient,
        string accessToken,
        string boxId,
        string fromDepartmentId,
        string toDepartmentId,
        byte[] documentBytes,
        bool useTestSignature,
        string fileName)
    {
        var documentContent = Convert.ToBase64String(documentBytes);
        var signedContent = new Dictionary<string, object?>
        {
            ["Content"] = documentContent
        };

        if (useTestSignature)
            signedContent["SignWithTestSignature"] = true;

        var documentAttachment = new Dictionary<string, object?>
        {
            ["SignedContent"] = signedContent,
            ["NeedRecipientSignature"] = true,
            ["TypeNamedId"] = "Nonformalized",
            ["Metadata"] = new[]
            {
                new Dictionary<string, string>
                {
                    ["Key"] = "FileName",
                    ["Value"] = fileName
                }
            }
        };

        var payload = new Dictionary<string, object?>
        {
            ["FromBoxId"] = boxId,
            ["IsInternal"] = true,
            ["FromDepartmentId"] = fromDepartmentId,
            ["ToDepartmentId"] = toDepartmentId,
            ["DocumentAttachments"] = new[] { documentAttachment }
        };

        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            $"https://diadoc-api.kontur.ru/V3/PostMessage?operationId={Uri.EscapeDataString(Guid.NewGuid().ToString("D"))}");

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

        using var response = await httpClient.SendAsync(request);
        var responseBody = await response.Content.ReadAsStringAsync();
        if (!response.IsSuccessStatusCode)
        {
            if (response.StatusCode == System.Net.HttpStatusCode.Forbidden &&
                responseBody.Contains("У вас нет доступа к документу", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "Диадок отклонил отправку: у текущего пользователя нет доступа к документу в выбранном подразделении отправителя. " +
                    "Обычно это означает, что внутренний маршрут между выбранными подразделениями недоступен для ваших прав.");
            }

            throw new InvalidOperationException(
                $"PostMessage failed: {(int)response.StatusCode} {response.ReasonPhrase}{Environment.NewLine}{responseBody}");
        }

        using var doc = JsonDocument.Parse(responseBody);
        var messageId = doc.RootElement.GetProperty("MessageId").GetString();
        if (string.IsNullOrWhiteSpace(messageId))
            throw new InvalidOperationException("В ответе PostMessage отсутствует MessageId.");

        string? entityId = null;
        foreach (var entity in doc.RootElement.GetProperty("Entities").EnumerateArray())
        {
            if (entity.TryGetProperty("EntityType", out var entityType) &&
                string.Equals(entityType.GetString(), "Attachment", StringComparison.OrdinalIgnoreCase))
            {
                entityId = entity.GetProperty("EntityId").GetString();
                break;
            }
        }

        if (string.IsNullOrWhiteSpace(entityId))
            throw new InvalidOperationException("В ответе PostMessage отсутствует EntityId вложения.");

        return new MessageCreationResult(messageId, entityId);
    }

    private async Task SendSignatureRequestAsync(
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

        // In production boxes Diadoc may accept PostMessage, but still return 409 for
        // PostMessagePatch for a while until the document state becomes patchable.
        const int maxAttempts = 24;
        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "https://diadoc-api.kontur.ru/V4/PostMessagePatch");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            request.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

            using var response = await httpClient.SendAsync(request);
            var responseBody = await response.Content.ReadAsStringAsync();
            if (response.IsSuccessStatusCode)
                return;

            var isStateConflict =
                response.StatusCode == System.Net.HttpStatusCode.Conflict &&
                responseBody.Contains("Текущее состояние документа не позволяет", StringComparison.OrdinalIgnoreCase);

            if (!isStateConflict || attempt == maxAttempts)
            {
                throw new InvalidOperationException(
                    $"PostMessagePatch failed: {(int)response.StatusCode} {response.ReasonPhrase}{Environment.NewLine}{responseBody}");
            }

            var delaySeconds = Math.Min(5, attempt);
            await Task.Delay(TimeSpan.FromSeconds(delaySeconds));
        }
    }

    private static bool IsPostMessagePatchStateConflict(InvalidOperationException ex)
    {
        return ex.Message.Contains("PostMessagePatch failed: 409", StringComparison.OrdinalIgnoreCase) &&
               ex.Message.Contains("Текущее состояние документа не позволяет", StringComparison.OrdinalIgnoreCase);
    }

    private async Task<IActionResult> HandleDownloadAsync(
        Func<string, DownloadRequestContext, Task<IActionResult>> downloadAction)
    {
        await LoadPageAsync();

        if (string.IsNullOrWhiteSpace(DownloadInput.BoxId))
            ModelState.AddModelError($"{nameof(DownloadInput)}.{nameof(DownloadInput.BoxId)}", "Укажите BoxId.");
        if (string.IsNullOrWhiteSpace(DownloadInput.MessageId))
            ModelState.AddModelError($"{nameof(DownloadInput)}.{nameof(DownloadInput.MessageId)}", "Укажите MessageId.");
        if (string.IsNullOrWhiteSpace(DownloadInput.EntityId))
            ModelState.AddModelError($"{nameof(DownloadInput)}.{nameof(DownloadInput.EntityId)}", "Укажите EntityId документа.");

        if (!ModelState.IsValid)
            return Page();

        try
        {
            var accessToken = await HttpContext.GetTokenAsync("access_token");
            if (string.IsNullOrWhiteSpace(accessToken))
                throw new InvalidOperationException("Не удалось получить access token.");

            return await downloadAction(
                accessToken,
                new DownloadRequestContext(
                    DownloadInput.BoxId!,
                    DownloadInput.MessageId!,
                    DownloadInput.EntityId!));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка скачивания документа");
            ModelState.AddModelError(string.Empty, ex.Message);
            return Page();
        }
    }

    private DownloadMode ParseDownloadMode(string? mode)
    {
        return Enum.TryParse<DownloadMode>(mode, true, out var parsedMode)
            ? parsedMode
            : DownloadMode.EmbeddedArchive;
    }

    private async Task<DocumentDownloadInfo> GetDocumentDownloadInfoAsync(
        string accessToken,
        string boxId,
        string messageId,
        string entityId)
    {
        var document = await _diadocApi.GetDocumentAsync(accessToken, boxId, messageId, entityId);
        var message = await _diadocApi.GetMessageAsync(accessToken, boxId, messageId, false, false);
        var documentContent = await _diadocApi.GetEntityContentAsync(accessToken, boxId, messageId, entityId);

        var signatureEntity = message.Entities
            .Where(x =>
                string.Equals(x.ParentEntityId, entityId, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(x.EntityType.ToString(), "Signature", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(x => x.RawCreationDate)
            .FirstOrDefault();

        byte[]? signatureContent = null;
        if (signatureEntity is not null && !string.IsNullOrWhiteSpace(signatureEntity.EntityId))
        {
            signatureContent = await _diadocApi.GetEntityContentAsync(
                accessToken,
                boxId,
                messageId,
                signatureEntity.EntityId);
        }

        var documentFileName = BuildFriendlyDocumentFileName(document.FileName, entityId);

        return new DocumentDownloadInfo(
            documentFileName,
            documentContent,
            signatureEntity?.EntityId,
            signatureContent);
    }

    private async Task<FileContentResult> CreateDocflowArchiveResultAsync(
        string accessToken,
        string boxId,
        string messageId,
        string entityId,
        string downloadFileName)
    {
        var zipResult = await WaitForDocumentZipAsync(accessToken, boxId, messageId, entityId, true);

        var zipBytes = await _diadocApi.GetFileFromShelfAsync(accessToken, zipResult.ZipFileNameOnShelf);
        return File(zipBytes, "application/zip", downloadFileName);
    }

    private Task<FileContentResult> CreateEmbeddedSignatureArchiveResultAsync(
        string accessToken,
        string boxId,
        string messageId,
        string entityId,
        string downloadFileName)
    {
        return CreateDocflowArchiveResultAsync(accessToken, boxId, messageId, entityId, downloadFileName);
    }

    private async Task<Diadoc.Api.Proto.Documents.DocumentZipGenerationResult> WaitForDocumentZipAsync(
        string accessToken,
        string boxId,
        string messageId,
        string entityId,
        bool fullDocflow)
    {
        const int maxAttempts = 10;

        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            var zipResult = await _diadocApi.GenerateDocumentZipAsync(accessToken, boxId, messageId, entityId, fullDocflow);
            if (!string.IsNullOrWhiteSpace(zipResult.ZipFileNameOnShelf))
                return zipResult;

            await Task.Delay(TimeSpan.FromSeconds(Math.Min(attempt, 3)));
        }

        throw new InvalidOperationException(
            "Diadoc еще не подготовил ZIP-архив документооборота. Повторите скачивание через несколько секунд.");
    }

    private async Task<Diadoc.Api.PrintFormResult> WaitForPrintFormAsync(
        string accessToken,
        string boxId,
        string messageId,
        string entityId)
    {
        const int maxAttempts = 10;

        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            var result = await _diadocApi.GeneratePrintFormAsync(accessToken, boxId, messageId, entityId);
            if (result.HasContent && result.Content?.Bytes is { Length: > 0 })
                return result;

            var delaySeconds = result.RetryAfter > 0 ? result.RetryAfter : Math.Min(attempt, 3);
            await Task.Delay(TimeSpan.FromSeconds(delaySeconds));
        }

        throw new InvalidOperationException(
            "Diadoc еще не подготовил PDF-представление документа. Повторите скачивание через несколько секунд.");
    }

    private static byte[] CreateSeparateFilesArchive(DocumentDownloadInfo documentInfo)
    {
        if (documentInfo.SignatureContent is null)
            throw new InvalidOperationException("Подпись для документа не найдена.");

        using var memoryStream = new MemoryStream();
        using (var archive = new System.IO.Compression.ZipArchive(memoryStream, System.IO.Compression.ZipArchiveMode.Create, true))
        {
            var documentEntry = archive.CreateEntry(documentInfo.DocumentFileName, System.IO.Compression.CompressionLevel.Fastest);
            using (var entryStream = documentEntry.Open())
            {
                entryStream.Write(documentInfo.DocumentContent, 0, documentInfo.DocumentContent.Length);
            }

            var signatureEntry = archive.CreateEntry(documentInfo.SignatureFileName, System.IO.Compression.CompressionLevel.Fastest);
            using (var entryStream = signatureEntry.Open())
            {
                entryStream.Write(documentInfo.SignatureContent, 0, documentInfo.SignatureContent.Length);
            }
        }

        return memoryStream.ToArray();
    }

    private static string BuildFriendlyDocumentFileName(string? rawFileName, string entityId)
    {
        var candidate = string.IsNullOrWhiteSpace(rawFileName) ? null : Path.GetFileName(rawFileName);
        if (string.IsNullOrWhiteSpace(candidate))
            return $"document-{entityId[..Math.Min(8, entityId.Length)]}.bin";

        candidate = SanitizeFileName(candidate);
        if (!LooksLikeOpaqueGeneratedFileName(candidate))
            return candidate;

        var extension = Path.GetExtension(candidate);
        if (string.IsNullOrWhiteSpace(extension))
            extension = ".bin";

        return $"document-{entityId[..Math.Min(8, entityId.Length)]}{extension}";
    }

    private static string BuildFriendlySignedPdfFileName(string rawPrintFormFileName, string documentFileName)
    {
        var candidate = SanitizeFileName(Path.GetFileName(rawPrintFormFileName));
        if (!LooksLikeOpaqueGeneratedFileName(candidate))
            return candidate;

        return BuildLabeledFileName(documentFileName, "Документ с подписью", ".pdf");
    }

    private static bool LooksLikeOpaqueGeneratedFileName(string fileName)
    {
        var baseName = Path.GetFileNameWithoutExtension(fileName);
        if (Guid.TryParse(baseName, out _))
            return true;

        return baseName.Length >= 24 && baseName.All(static ch => char.IsLetterOrDigit(ch) || ch == '-' || ch == '_');
    }

    private static string SanitizeFileName(string fileName)
    {
        var invalidChars = Path.GetInvalidFileNameChars();
        var sanitized = new string(fileName.Select(ch => invalidChars.Contains(ch) ? '_' : ch).ToArray()).Trim();
        return string.IsNullOrWhiteSpace(sanitized) ? "document.bin" : sanitized;
    }

    private static string BuildLabeledFileName(string sourceFileName, string label, string? forcedExtension = null)
    {
        var baseName = Path.GetFileNameWithoutExtension(sourceFileName);
        baseName = string.IsNullOrWhiteSpace(baseName) ? "document" : baseName;
        var extension = string.IsNullOrWhiteSpace(forcedExtension)
            ? Path.GetExtension(sourceFileName)
            : forcedExtension;

        if (string.IsNullOrWhiteSpace(extension))
            extension = ".bin";

        return SanitizeFileName($"{label} - {baseName}{extension}");
    }

    public class SignatureRequestForm
    {
        public string? OrganizationBoxId { get; set; }
        public string? BoxId { get; set; }
        public string? FromDepartmentId { get; set; }
        public string? InternalRecipientDepartmentId { get; set; }
        public string? InternalRecipientLoginOrUserId { get; set; }
        public string? SignatureRecipientLoginOrUserId { get; set; }
        public string? Comment { get; set; }
        public IFormFile? Document { get; set; }
    }

    public class DownloadDocumentForm
    {
        public string? BoxId { get; set; }
        public string? MessageId { get; set; }
        public string? EntityId { get; set; }
        public string? Mode { get; set; }
    }

    private sealed record EmployeeInfo(string UserId, string? DepartmentId, string? Login);
    private sealed record DepartmentInfo(string DepartmentId, string DepartmentName);
    private sealed record InternalMessageRoute(
        string FromDepartmentId,
        string ToDepartmentId,
        string FromDepartmentName,
        string ToDepartmentName);
    private sealed record MessageCreationResult(string MessageId, string EntityId);
    private sealed record DocumentDownloadInfo(
        string DocumentFileName,
        byte[] DocumentContent,
        string? SignatureEntityId,
        byte[]? SignatureContent)
    {
        public string OriginalDownloadFileName => BuildLabeledFileName(DocumentFileName, "Исходный документ");
        public string SignedPdfFileName => BuildLabeledFileName(DocumentFileName, "Документ с подписью", ".pdf");
        public string SignatureFileName => BuildLabeledFileName(DocumentFileName, "Файл подписи", ".sgn");
        public string DocflowArchiveFileName => BuildLabeledFileName(DocumentFileName, "Полный документооборот", ".zip");
        public string EmbeddedArchiveFileName => BuildLabeledFileName(DocumentFileName, "Документ с внутренней подписью", ".zip");
        public string SeparateArchiveFileName => BuildLabeledFileName(DocumentFileName, "Исходный документ и подпись", ".zip");
    }

    private sealed record DownloadRequestContext(string BoxId, string MessageId, string EntityId);

    private enum DownloadMode
    {
        EmbeddedArchive,
        SeparateArchive,
        Document,
        Signature
    }
}

