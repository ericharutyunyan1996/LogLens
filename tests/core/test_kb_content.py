"""Content checks for the researched knowledge-base expansion in ``builtin.toml``.

Entries after the expansion marker must load, be reachable (every pattern entry is triggered by a realistic synthetic
example line, event entries are found by provider + event id, code entries own their codes) and must stay quiet on
ordinary log lines. All example lines are synthetic.
"""

from __future__ import annotations

import re
from functools import cache
from importlib import resources

import pytest

from loglens.core.kb import KBEntry, KnowledgeBase

MARKER = "# ==== kb-expansion-2026-11 ===="
SECTION_HEADER = re.compile(r"^# -{20,} ", re.MULTILINE)
ID_FORMAT = re.compile(
    r"^(?:event|code|dotnet|iis|sql|java|python|node|pg|mysql|nginx|apache|linux|k8s|docker|tls|net)-[a-z0-9]+(?:-[a-z0-9]+)*$"
)
MIN_NEW_ENTRIES = 120


@cache
def _builtin_text() -> str:
    return resources.files("loglens.core.kb").joinpath("builtin.toml").read_text(encoding="utf-8")


@cache
def _old_and_new() -> tuple[KnowledgeBase, KnowledgeBase]:
    head, marker, tail = _builtin_text().partition(MARKER)
    assert marker, "expansion marker missing from builtin.toml"
    return KnowledgeBase.from_toml(head), KnowledgeBase.from_toml(tail)


def _new_entries() -> list[KBEntry]:
    return _old_and_new()[1].entries


def _new_by_id() -> dict[str, KBEntry]:
    return {entry.id: entry for entry in _new_entries()}


def _log(message: str, level: str = "ERROR") -> str:
    """A typical application log line: timestamp, level, message."""
    return f"2026-11-13 10:15:02.123 {level} {message}"


def _event(provider: str, event_id: int, message: str = "Synthetic event message.", details: str = "{}") -> str:
    """A Windows event in LogLens' one-line form (see EventRecord.to_line)."""
    return f"2026-11-13 10:15:02.123 +00:00 Error [System] {provider} ({event_id}) — {message} ‖ {details}"


def _explains(kb: KnowledgeBase, line: str, entry: KBEntry) -> bool:
    return any((f.title, f.explanation) == (entry.title, entry.explanation) for f in kb.explain(line))


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return KnowledgeBase.builtin()


# ---- realistic positive examples, one per new pattern entry ---------------------------------------------------------
_IIS = "2026-11-13 10:15:02 10.0.0.5 GET /app/ - 443 - 10.0.0.9 Mozilla/5.0 -"
_HTTPERR = "2026-11-13 10:15:02 10.0.0.9 51234 10.0.0.5 443 HTTP/1.1 GET /api/orders -"
_SQLLOG = "2026-11-13 10:15:02.12 spid57      "
_PG = "2026-11-13 10:15:02.123 UTC [4242] "
_NGINX = "2026/11/13 10:15:02 [error] 31#31: *1042 "
_APACHE = "[Fri Nov 13 10:15:02.123456 2026] "
_SYSLOG = "Nov 13 10:15:02 web1 kernel: "
_K8S = "2026-11-13T10:15:02Z Warning "

PATTERN_EXAMPLES: dict[str, str] = {
    # Windows / Kerberos / codes with text
    "event-kdc-etype": _log("Kerberos: KDC returned KDC_ERR_ETYPE_NOTSUPP for HTTP/web01.example.com"),
    "event-kerberos-ap-err-modified": _log(
        "The Kerberos client received a KRB_AP_ERR_MODIFIED error from server web01$"
    ),
    "net-kerberos-principal-unknown": _log("Kerberos error 0x7 KDC_ERR_S_PRINCIPAL_UNKNOWN for MSSQLSvc/db01:1433"),
    "net-kerberos-clock-skew": _log("kinit: Clock skew too great while getting initial credentials"),
    "net-kerberos-logon-rejected": _log("Pre-authentication failed: KDC_ERR_PREAUTH_FAILED for svc-batch@EXAMPLE.COM"),
    "event-netlogon-trust": _log(
        "Logon failed: The trust relationship between this workstation and the primary domain failed."
    ),
    "code-activation-failed": _log("Activation failed: No Key Management Service (KMS) could be contacted."),
    "code-rpc-unavailable": _log("Certificate enrollment failed: The RPC server is unavailable."),
    "code-rpc-call-failed": _log("DISM failed: The remote procedure call failed."),
    "code-class-not-registered": _log("Retrieving the COM class factory failed: Class not registered"),
    "code-bad-image-format": _log("Failed to start worker: worker.exe is not a valid Win32 application."),
    "code-module-not-found": _log("LoadLibrary(native.dll) failed: The specified module could not be found."),
    "code-procedure-not-found": _log("GetProcAddress failed: The specified procedure could not be found."),
    "code-insufficient-resources": _log(
        "CreateThread failed: Insufficient system resources exist to complete the requested service."
    ),
    "code-io-device-error": _log("Copy failed: The request could not be performed because of an I/O device error."),
    "code-semaphore-timeout": _log("Write to \\\\files01\\share failed: The semaphore timeout period has expired."),
    "code-network-path": _log("Cannot open \\\\files01\\reports: The network path was not found."),
    "code-logon-failure-win32": _log("LogonUser failed: The user name or password is incorrect."),
    "code-service-control": _log(
        "StartService failed: The service cannot be started, either because it is disabled or because it has no"
        " enabled devices associated with it."
    ),
    "code-wait-timeout": _log("System.ComponentModel.Win32Exception (258): The wait operation timed out."),
    "code-operation-aborted": _log(
        "SocketException (995): The I/O operation has been aborted because of either a thread exit or an"
        " application request."
    ),
    "code-wu-component-store": _log("Servicing failed: The component store has been corrupted."),
    # bug checks: BugCheck 1001 text, WinDbg lines, symbolic names and Kernel-Power 41 data
    "code-bugcheck-driver-fault": _event(
        "Microsoft-Windows-WER-SystemErrorReporting",
        1001,
        "The computer has rebooted from a bugcheck. The bugcheck was: 0x000000d1 (0x0, 0x2, 0x0, 0x1).",
    ),
    "code-bugcheck-memory-corruption": _log("Crash analysis: MEMORY_MANAGEMENT (1a) in ntoskrnl.exe"),
    "code-bugcheck-power-state": _event(
        "Microsoft-Windows-Kernel-Power",
        41,
        "The system has rebooted without cleanly shutting down first.",
        '{"data": {"BugcheckCode": "159", "PowerButtonTimestamp": "0"}}',
    ),
    "code-bugcheck-critical-process": _log("BugCheck EF, {ffffd28c, 0, 0, 0}"),
    "code-bugcheck-hardware": _log("Stop code WHEA_UNCORRECTABLE_ERROR after resume"),
    "code-bugcheck-dpc-watchdog": _event(
        "Microsoft-Windows-WER-SystemErrorReporting",
        1001,
        "The computer has rebooted from a bugcheck. The bugcheck was: 0x00000133 (0x1, 0x1e00, 0x0, 0x0).",
    ),
    "code-bugcheck-storage": _log("Blue screen: KERNEL_DATA_INPAGE_ERROR"),
    "code-bugcheck-security-check": _log("Bug check code: 0x139 KERNEL_SECURITY_CHECK_FAILURE"),
    "code-bugcheck-video": _log("Display driver crash VIDEO_TDR_FAILURE in nvlddmkm.sys"),
    "code-bugcheck-manual": _log("Dump created: MANUALLY_INITIATED_CRASH"),
    # TLS / certificates
    "tls-untrusted-issuer": _log("request to https://api.example.com failed: unable to get local issuer certificate"),
    "tls-self-signed-chain": _log("Error: self-signed certificate in certificate chain"),
    "tls-hostname-mismatch": _log(
        "Error [ERR_TLS_CERT_ALTNAME_INVALID]: Hostname/IP does not match certificate's altnames: Host: api.example.com"
    ),
    "tls-wrong-version-number": _log("curl: (35) error:0A00010B:SSL routines::wrong version number"),
    "tls-protocol-mismatch": _log(
        "Win32Exception: The client and server cannot communicate, because they do not possess a common algorithm."
    ),
    "tls-revocation-check": _log("Certificate chain status: RevocationStatusUnknown, OfflineRevocation"),
    "tls-cert-expired": _log("Error: certificate has expired code=CERT_HAS_EXPIRED"),
    "code-sec-untrusted-root": _log(
        "SqlException: (provider: SSL Provider, error: 0 - The certificate chain was issued by an authority that is"
        " not trusted.)"
    ),
    "code-sec-wrong-principal": _log("SqlException: Cannot generate SSPI context."),
    "code-sec-auth-failed": _log("SSPI handshake failed: No authority could be contacted for authentication."),
    "code-sec-key-access": _log("System.Security.Cryptography.CryptographicException: Keyset does not exist"),
    "code-winhttp-tls": _log("WinHttpSendRequest failed: An error occurred in the secure channel support"),
    "code-winhttp-connection": _log("Download failed: The connection with the server was terminated abnormally"),
    # sockets and HTTP access logs
    "net-address-in-use": _log("Error: listen EADDRINUSE: address already in use :::3000"),
    "net-connection-aborted": _log(
        "IOException: An established connection was aborted by the software in your host machine."
    ),
    "net-connection-timed-out": _log("Error: connect ETIMEDOUT 10.0.0.12:443"),
    "net-unreachable": _log("connect to 10.20.0.5 port 5432 failed: No route to host"),
    "net-no-buffer-space": _log(
        "SocketException (10055): An operation on a socket could not be performed because the system lacked"
        " sufficient buffer space or because a queue was full."
    ),
    "net-socket-forbidden": _log(
        "SocketException (10013): An attempt was made to access a socket in a way forbidden by its access permissions."
    ),
    "net-address-not-available": _log("connect() failed: Cannot assign requested address"),
    "net-dns-temporary": _log("socket.gaierror: [Errno -3] Temporary failure in name resolution"),
    "net-econnreset": _log("Error: read ECONNRESET at TCP.onStreamRead"),
    "net-broken-pipe": _log("BrokenPipeError: [Errno 32] Broken pipe"),
    "net-context-deadline": _log('Get "https://registry.example.com/v2/": context deadline exceeded'),
    "net-http-access-5xx": '10.0.0.5 - - [13/Nov/2026:10:15:02 +0000] "GET /api/orders HTTP/1.1" 502 157 "-" "curl"',
    "net-http-access-client-limits": (
        '10.0.0.5 - - [13/Nov/2026:10:15:03 +0000] "POST /api/login HTTP/1.1" 429 52 "-" "python-requests/2.32"'
    ),
    # .NET / ASP.NET Core
    "dotnet-object-disposed": _log("System.ObjectDisposedException: Cannot access a disposed object."),
    "dotnet-operation-canceled": _log("System.OperationCanceledException: The operation was canceled."),
    "dotnet-http-request-failed": _log(
        "System.Net.Http.HttpRequestException: Response status code does not indicate success: 404 (Not Found)."
    ),
    "dotnet-sql-pool-exhausted": _log(
        "InvalidOperationException: Timeout expired. The timeout period elapsed prior to obtaining a connection from"
        " the pool."
    ),
    "dotnet-sql-transport-error": _log(
        "SqlException: A transport-level error has occurred when receiving results from the server."
    ),
    "dotnet-common-bugs": _log("System.InvalidOperationException: Sequence contains no elements"),
    "dotnet-type-initializer": _log(
        "System.TypeInitializationException: The type initializer for 'App.Settings' threw an exception."
    ),
    "dotnet-load-failure": _log(
        "System.DllNotFoundException: Unable to load DLL 'libsodium' or one of its dependencies"
    ),
    "dotnet-di-unresolved": _log(
        "InvalidOperationException: Unable to resolve service for type 'App.IClock' while attempting to activate"
        " 'App.Worker'."
    ),
    "dotnet-data-protection-key": _log("The key {3f2a9c1e-0000-4000-8000-123456789abc} was not found in the key ring."),
    "dotnet-tls-transport": _log(
        "System.IO.IOException: Received an unexpected EOF or 0 bytes from the transport stream."
    ),
    "dotnet-jwt-validation": _log(
        "Bearer was not authenticated: IDX10223: Lifetime validation failed. The token is expired."
    ),
    "dotnet-aspnetcore-unhandled": _log(
        "Microsoft.AspNetCore.Diagnostics.ExceptionHandlerMiddleware: An unhandled exception has occurred while"
        " executing the request."
    ),
    "dotnet-aspnetcore-startup-failed": _log(
        "Microsoft.Extensions.Hosting.Internal.Host: Hosting failed to start", "CRIT"
    ),
    "dotnet-threadpool-starvation": _log(
        'As of "11/13/2026 10:15:02 +00:00", the heartbeat has been running for "00:00:03.2" which is longer than'
        ' "00:00:01". This could be caused by thread pool starvation.',
        "WARN",
    ),
    # IIS error pages, W3C rows and HTTPERR rows
    "iis-500-19": f"{_IIS} 500 19 13 31",
    "iis-500-21-pipeline": _log(
        'HTTP Error 500.21 - Internal Server Error: Handler "PageHandlerFactory-Integrated" has a bad module'
        ' "ManagedPipelineHandler" in its module list'
    ),
    "iis-403-14": _log("HTTP Error 403.14 - Forbidden: The Web server is configured to not list the contents."),
    "iis-404-substatus": f"{_IIS} 404 13 0 2",
    "iis-401-handshake": f"{_IIS} 401 2 5 15",
    "iis-401-failed": f"{_IIS} 401 1 1326 31",
    "iis-503-page": _log("Server returned: HTTP Error 503. The service is unavailable."),
    "iis-502-3": f"{_IIS} 502 3 12002 120015",
    "iis-ancm-start-failure": _log("HTTP Error 500.30 - ASP.NET Core app failed to start"),
    "iis-ancm-config": _log("HTTP Error 500.37 - ANCM Failed to Start Within Startup Time Limit"),
    "iis-client-disconnected": f"{_IIS} 200 0 64 91234",
    "iis-httperr-abandoned": f"{_HTTPERR} - 1 Connection_Abandoned_By_ReqQueue DefaultAppPool",
    "iis-httperr-pool-unavailable": f"{_HTTPERR} 503 - AppOffline DefaultAppPool",
    "iis-httperr-idle": "2026-11-13 10:15:02 10.0.0.9 51236 10.0.0.5 443 - - - - - Timer_ConnectionIdle -",
    "iis-httperr-client": f"{_HTTPERR} 400 - Hostname -",
    # SQL Server
    "sql-log-full": f"{_SQLLOG}The transaction log for database 'Sales' is full due to 'LOG_BACKUP'.",
    "sql-filegroup-full": (
        f"{_SQLLOG}Could not allocate space for object 'dbo.Orders'.'PK_Orders' in database 'Sales' because the"
        " 'PRIMARY' filegroup is full."
    ),
    "sql-slow-io": (
        f"{_SQLLOG}SQL Server has encountered 4 occurrence(s) of I/O requests taking longer than 15 seconds to"
        " complete on file [D:\\Data\\Sales.mdf] in database id 5."
    ),
    "sql-non-yielding": f"{_SQLLOG}Process 0:0:0 (0x1a2c) Worker 0x1A2B appears to be non-yielding on Scheduler 3.",
    "sql-io-error": f"{_SQLLOG}SQL Server detected a logical consistency-based I/O error: incorrect checksum.",
    "sql-memory-pressure": f"{_SQLLOG}There is insufficient system memory in resource pool 'default' to run this.",
    "sql-data-integrity": _log("SqlException: Violation of PRIMARY KEY constraint 'PK_Orders'."),
    "sql-lock-timeout": _log("SqlException: Lock request time out period exceeded."),
    "sql-invalid-object": _log("SqlException: Invalid object name 'dbo.OrderLines'."),
    "sql-cannot-open-database": _log('SqlException: Cannot open database "Sales" requested by the login.'),
    "sql-login-reason": (
        f"{_SQLLOG}Login failed for user 'app'. Reason: Password did not match that for the login provided."
    ),
    "sql-login-integrated": f"{_SQLLOG}Login failed for user 'NT AUTHORITY\\ANONYMOUS LOGON'. [CLIENT: 10.0.0.9]",
    "sql-backup-failed": f"{_SQLLOG}BACKUP failed to complete the command BACKUP LOG Sales.",
    "sql-agent-job-failed": _log(
        "SQL Server Scheduled Job 'Nightly ETL' - The job failed.  The Job was invoked by Schedule 3"
    ),
    "sql-database-suspect": _log("Database 'Sales' cannot be opened. It has been marked SUSPECT by recovery."),
    # Java
    "java-oom-heap": _log('Exception in thread "main" java.lang.OutOfMemoryError: Java heap space'),
    "java-oom-metaspace": _log("java.lang.OutOfMemoryError: Metaspace"),
    "java-oom-native": _log("java.lang.OutOfMemoryError: unable to create native thread"),
    "java-jvm-crash": "# A fatal error has been detected by the Java Runtime Environment:",
    "java-stack-overflow": _log('Exception in thread "worker-1" java.lang.StackOverflowError'),
    "java-class-loading": _log("java.lang.NoClassDefFoundError: Could not initialize class com.example.Config"),
    "java-linkage-error": _log("java.lang.NoSuchMethodError: 'void com.example.Client.connect(int)'"),
    "java-socket-timeout": _log("java.net.SocketTimeoutException: Read timed out"),
    "java-ssl-handshake": _log("javax.net.ssl.SSLHandshakeException: Received fatal alert: handshake_failure"),
    "java-pkix": _log("ValidatorException: PKIX path building failed: unable to find valid certification path"),
    "java-unknown-host": _log("java.net.UnknownHostException: db01.internal.example"),
    "java-npe": _log('java.lang.NullPointerException: Cannot invoke "String.length()" because "name" is null'),
    "java-hikari-pool": _log("HikariPool-1 - Connection is not available, request timed out after 30000ms."),
    # Python
    "python-traceback": "2026-11-13 10:15:02,123 ERROR app: Traceback (most recent call last):",
    "python-memory-error": _log("worker crashed: MemoryError"),
    "python-recursion": _log("RecursionError: maximum recursion depth exceeded while calling a Python object"),
    "python-import-error": _log("ModuleNotFoundError: No module named 'yaml'"),
    "python-requests-failed": _log(
        "ConnectionError: HTTPSConnectionPool(host='api.example.com', port=443): Max retries exceeded with url: /v1"
    ),
    "python-gunicorn-worker": "[2026-11-13 10:15:02 +0000] [1] [CRITICAL] WORKER TIMEOUT (pid:42)",
    # Node.js
    "node-heap-oom": "FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory",
    "node-cannot-find-module": _log("Error: Cannot find module 'express'"),
    "node-unhandled-rejection": _log("[UnhandledPromiseRejection: This error originated in an async function]"),
    "node-headers-sent": _log("Error [ERR_HTTP_HEADERS_SENT]: Cannot set headers after they are sent to the client"),
    "node-max-listeners": _log("(node:1234) MaxListenersExceededWarning: Possible EventEmitter memory leak", "WARN"),
    # PostgreSQL
    "pg-too-many-connections": f"{_PG}FATAL:  sorry, too many clients already",
    "pg-deadlock-serialization": f"{_PG}ERROR:  deadlock detected",
    "pg-connect-rejected": f'{_PG}FATAL:  password authentication failed for user "app"',
    "pg-statement-canceled": f"{_PG}ERROR:  canceling statement due to statement timeout",
    "pg-not-ready": f"{_PG}FATAL:  the database system is starting up",
    "pg-out-of-shared-memory": f"{_PG}ERROR:  out of shared memory",
    "pg-wraparound": f'{_PG}WARNING:  database "sales" must be vacuumed within 9871234 transactions',
    "pg-backend-crash": f"{_PG}LOG:  server process (PID 5012) was terminated by signal 9: Killed",
    "pg-data-error": f'{_PG}ERROR:  duplicate key value violates unique constraint "orders_pkey"',
    "pg-checkpoints-frequent": f"{_PG}LOG:  checkpoints are occurring too frequently (12 seconds apart)",
    # MySQL / MariaDB
    "mysql-too-many-connections": _log("ERROR 1040 (HY000): Too many connections"),
    "mysql-lock-conflict": _log(
        "ERROR 1213 (40001): Deadlock found when trying to get lock; try restarting transaction"
    ),
    "mysql-connection-lost": _log("ERROR 2006 (HY000): MySQL server has gone away"),
    "mysql-access-denied": _log("ERROR 1045 (28000): Access denied for user 'app'@'10.0.0.9' (using password: YES)"),
    "mysql-cannot-connect": _log("ERROR 2003 (HY000): Can't connect to MySQL server on 'db01:3306' (111)"),
    "mysql-packet-too-large": _log("ERROR 1153 (08S01): Got a packet bigger than 'max_allowed_packet' bytes"),
    "mysql-missing-object": _log("ERROR 1146 (42S02): Table 'shop.orders' doesn't exist"),
    "mysql-data-error": _log("ERROR 1062 (23000): Duplicate entry '42' for key 'orders.PRIMARY'"),
    "mysql-read-only": _log("ERROR 1290 (HY000): The MySQL server is running with the --read-only option"),
    "mysql-aborted-connection": (
        "2026-11-13T10:15:02.123456Z 812 [Note] Aborted connection 812 to db: 'shop' user: 'app' host: '10.0.0.9'"
    ),
    # nginx
    "nginx-upstream-timeout": (
        f"{_NGINX}upstream timed out (110: Connection timed out) while reading response header from upstream"
    ),
    "nginx-upstream-unavailable": f"{_NGINX}connect() failed (111: Connection refused) while connecting to upstream",
    "nginx-worker-connections": "2026/11/13 10:15:02 [alert] 31#31: 1024 worker_connections are not enough",
    "nginx-upstream-closed": f"{_NGINX}upstream prematurely closed connection while reading response header",
    "nginx-body-too-large": f"{_NGINX}client intended to send too large body: 10485760 bytes",
    "nginx-upstream-big-header": f"{_NGINX}upstream sent too big header while reading response header from upstream",
    "nginx-limit-req": f'{_NGINX}limiting requests, excess: 10.500 by zone "api"',
    "nginx-redirect-cycle": f'{_NGINX}rewrite or internal redirection cycle while internally redirecting to "/"',
    "nginx-fastcgi-script-unknown": f'{_NGINX}FastCGI sent in stderr: "Primary script unknown"',
    "nginx-file-not-found": f'{_NGINX}open() "/usr/share/nginx/html/favicon.ico" failed (2: No such file or directory)',
    # Apache httpd
    "apache-max-request-workers": (
        f"{_APACHE}[mpm_event:error] [pid 100:tid 140] AH00484: server reached MaxRequestWorkers setting"
    ),
    "apache-client-denied": f"{_APACHE}[authz_core:error] [pid 101] AH01630: client denied by server configuration",
    "apache-servername": "AH00558: httpd: Could not reliably determine the server's fully qualified domain name",
    "apache-proxy-backend": f"{_APACHE}[proxy:error] [pid 102] AH00957: HTTP: attempt to connect to 10.0.0.7:80 failed",
    "apache-child-crash": f"{_APACHE}[core:notice] [pid 99] AH00052: child pid 1234 exit signal Segmentation fault",
    # Linux
    "linux-oom-killer": f"{_SYSLOG}Out of memory: Killed process 4321 (java) total-vm:8123456kB",
    "linux-segfault": f"{_SYSLOG}myapp[4321]: segfault at 0 ip 00007f3a2b1c0d10 sp 00007ffd5e2a8c40 error 4",
    "linux-too-many-open-files": "Nov 13 10:15:02 web1 app[812]: accept() failed: Too many open files",
    "linux-kernel-stall": f"{_SYSLOG}INFO: task jbd2/sda1-8:312 blocked for more than 120 seconds.",
    "linux-fs-error": f"{_SYSLOG}EXT4-fs error (device sda1): ext4_find_entry:1455: inode #2: comm ls",
    "linux-disk-io-error": f"{_SYSLOG}blk_update_request: I/O error, dev sdb, sector 123456 op 0x0:(READ)",
    "linux-conntrack-full": f"{_SYSLOG}nf_conntrack: nf_conntrack: table full, dropping packet",
    "linux-kernel-panic": f"{_SYSLOG}Kernel panic - not syncing: Fatal exception",
    "linux-hardware-error": f"{_SYSLOG}mce: [Hardware Error]: Machine check events logged",
    "linux-systemd-failed": "Nov 13 10:15:02 web1 systemd[1]: app.service: Main process exited, code=exited, status=1",
    "linux-ssh-failed-password": (
        "Nov 13 10:15:02 web1 sshd[2201]: Failed password for invalid user admin from 203.0.113.5 port 52811 ssh2"
    ),
    "linux-cannot-allocate": "-bash: fork: retry: Resource temporarily unavailable",
    "linux-nfs-not-responding": f"{_SYSLOG}nfs: server files01 not responding, still trying",
    "linux-syn-flood": f"{_SYSLOG}TCP: request_sock_TCP: Possible SYN flooding on port 443. Sending cookies.",
    # Kubernetes / Docker
    "k8s-oomkilled": "    Last State:  Terminated   Reason: OOMKilled   Exit Code: 137",
    "k8s-crashloop": f"{_K8S}BackOff pod/api-7c9 Back-off restarting failed container api in pod api-7c9",
    "k8s-image-pull": f'{_K8S}Failed pod/api-7c9 Failed to pull image "registry.example.com/api:1.4": manifest unknown',
    "k8s-failed-scheduling": f"{_K8S}FailedScheduling pod/api-7c9 0/3 nodes are available: 3 Insufficient memory.",
    "k8s-probe-failed": f"{_K8S}Unhealthy pod/api-7c9 Liveness probe failed: HTTP probe failed with statuscode: 500",
    "k8s-evicted": f"{_K8S}Evicted pod/api-7c9 The node was low on resource: memory.",
    "k8s-mount-failed": f'{_K8S}FailedMount pod/api-7c9 MountVolume.SetUp failed for volume "config"',
    "k8s-config-error": f"{_K8S}Failed pod/api-7c9 Error: couldn't find key DB_PASSWORD in Secret default/api",
    "k8s-exec-format": "exec /usr/local/bin/docker-entrypoint.sh: exec format error",
    "k8s-node-not-ready": "2026-11-13T10:15:02Z Normal NodeNotReady node/worker-2 Node status is now: NodeNotReady",
    "docker-daemon-unreachable": "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is it running?",
}

# ---- ordinary, harmless lines: the new entries must not flag any of them as "important" -----------------------------
HARMLESS_LINES: list[str] = [
    _log("Application started in 2.3 seconds", "INFO"),
    _log("Listening on http://0.0.0.0:8080", "INFO"),
    "2026-11-13 10:15:02 [INF] Now listening on: https://localhost:5001",
    _log("Connection pool initialized (max pool size: 100)", "INFO"),
    '127.0.0.1 - - [13/Nov/2026:10:15:02 +0000] "GET /index.html HTTP/1.1" 200 5120 "-" "Mozilla/5.0"',
    '10.0.0.5 - - [13/Nov/2026:10:15:03 +0000] "POST /api/orders HTTP/1.1" 201 87 "-" "curl/8.5"',
    '10.0.0.5 - - [13/Nov/2026:10:15:04 +0000] "GET /logo.png HTTP/1.1" 304 0 "-" "Mozilla/5.0"',
    f"{_IIS} 200 0 0 31",
    f"{_IIS} 304 0 0 0",
    f"{_IIS} 302 0 0 15",
    _log("Scan complete: no errors found", "INFO"),
    _log("Retry succeeded after 2 attempts", "INFO"),
    _log("timeout set to 30s", "DEBUG"),
    _log("Processed 120 records, 0 errors, 0 warnings", "INFO"),
    _log("Health check passed: database reachable", "INFO"),
    _log("TLS handshake completed with api.example.com (TLSv1.3)", "INFO"),
    _log("Loaded certificate CN=www.example.com, expires 2027-05-01", "INFO"),
    _log("Generating self-signed certificate for localhost", "INFO"),
    _log("Deadlock detection enabled (interval 5s)", "INFO"),
    _log("deadlock check finished: no deadlock detected", "INFO"),
    _log("max_connections = 200", "INFO"),
    _log("Worker timeout configured to 30 seconds", "INFO"),
    _log("Cache evicted 12 entries", "INFO"),
    _log("Readiness probe succeeded", "INFO"),
    _log("Pod api-7c9 scheduled to node worker-1", "INFO"),
    _log('Pulled image "nginx:1.27" successfully', "INFO"),
    "Nov 13 10:15:02 web1 systemd[1]: Started Daily apt download activities.",
    "Nov 13 10:15:02 web1 systemd[1]: nginx.service: Main process exited, code=exited, status=0/SUCCESS",
    "Nov 13 10:15:02 web1 sshd[812]: Accepted publickey for deploy from 10.0.0.7 port 51234 ssh2",
    f"{_SYSLOG}EXT4-fs (sda1): mounted filesystem with ordered data mode",
    "2026/11/13 10:15:02 [notice] 1#1: start worker processes",
    f"{_APACHE}[mpm_event:notice] [pid 100:tid 140] AH00489: Apache/2.4.62 configured -- resuming normal operations",
    f"{_PG}LOG:  database system is ready to accept connections",
    "2026-11-13T10:15:02.123456Z 0 [System] [MY-010931] /usr/sbin/mysqld: ready for connections.",
    f"{_SQLLOG}SQL Server is now ready for client connections. This is an informational message only.",
    f"{_SQLLOG}Login succeeded for user 'app'. Connection made using SQL Server authentication.",
    _log("Backup completed successfully (BACKUP DATABASE app)", "INFO"),
    _log("Request GET /health completed in 3 ms with status 200", "INFO"),
    _log("Slow request: 1200 ms (threshold 1000 ms)", "WARN"),
    _log("Connection established to db01:5432", "INFO"),
    _log("Scheduled task 'cleanup' finished with exit code 0", "INFO"),
    _log("Invalid user input from form 'signup' rejected by validation", "INFO"),
    _log("Unknown database type 'h2', defaulting to sqlite", "INFO"),
    _log("Kestrel listening on port 5000, heartbeat interval 1s", "INFO"),
    _log("Readiness: 3/3 nodes are ready", "INFO"),
    _log("Application startup complete.", "INFO"),
    _log("No route changes detected", "INFO"),
    _log("secret token not found in cache, loading from vault", "INFO"),
    _log("Support note: user searched for 'bug check a' in the help center", "INFO"),
    _log("The bugcheck was: 0x00000000 (no crash recorded)", "INFO"),
    _log("Configured worker_connections 1024", "INFO"),
    _log("Evicted pod count: 0", "INFO"),
    _log("Token refreshed; expires in 3600 s", "INFO"),
]


# ---- tests -----------------------------------------------------------------------------------------------------------
def test_kb_loads_with_unique_ids(kb: KnowledgeBase) -> None:
    ids = [entry.id for entry in kb.entries]
    assert len(ids) == len(set(ids)), "duplicate KB ids"
    new = _new_entries()
    assert len(new) >= MIN_NEW_ENTRIES
    assert {entry.id for entry in new} <= set(ids)
    for entry in new:
        assert ID_FORMAT.match(entry.id), entry.id
        assert entry.title and entry.explanation and entry.causes and entry.steps, entry.id
        assert entry.event_ids or entry.codes or entry.patterns, entry.id


def test_new_entries_are_distinguishable(kb: KnowledgeBase) -> None:
    keys = [(entry.title, entry.explanation) for entry in kb.entries]
    assert len(keys) == len(set(keys)), "two entries share title and explanation"


def test_every_section_cites_sources() -> None:
    tail = _builtin_text().partition(MARKER)[2]
    for section in SECTION_HEADER.split(tail):
        if "[[entry]]" in section:
            assert "# src: " in section, section.splitlines()[0]


def test_every_new_pattern_entry_has_an_example() -> None:
    with_patterns = {entry.id for entry in _new_entries() if entry.patterns}
    assert set(PATTERN_EXAMPLES) == with_patterns


@pytest.mark.parametrize(("entry_id", "line"), sorted(PATTERN_EXAMPLES.items()))
def test_pattern_example_is_explained(kb: KnowledgeBase, entry_id: str, line: str) -> None:
    entry = _new_by_id()[entry_id]
    assert _explains(kb, line, entry), [f.title for f in kb.explain(line)]


def test_event_entries_are_found_and_new(kb: KnowledgeBase) -> None:
    old = _old_and_new()[0]
    for entry in _new_entries():
        for provider in entry.providers:
            for event_id in entry.event_ids:
                assert entry.id in [e.id for e in kb.lookup_event(provider, event_id)], (entry.id, provider, event_id)
                assert not old.lookup_event(provider, event_id), f"{provider} {event_id} already explained"
                assert _explains(kb, _event(provider, event_id), entry), (entry.id, provider, event_id)


def test_code_entries_own_their_codes(kb: KnowledgeBase) -> None:
    old_codes = {code for entry in _old_and_new()[0].entries for code in entry.codes}
    for entry in _new_entries():
        for code in entry.codes:
            assert code not in old_codes, f"0x{code:08X} already explained by an existing entry"
            assert _explains(kb, _log(f"operation failed, hr=0x{code:08X}"), entry), (entry.id, f"0x{code:08X}")


@pytest.mark.parametrize("line", HARMLESS_LINES)
def test_ordinary_lines_raise_no_important_findings(kb: KnowledgeBase, line: str) -> None:
    new_keys = {(entry.title, entry.explanation) for entry in _new_entries()}
    flagged = [f.title for f in kb.explain(line) if f.noise == "important" and (f.title, f.explanation) in new_keys]
    assert not flagged
