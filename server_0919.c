#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <crypt.h>

#define PORT 50919
#define MAX_PAYLOAD 4096
#define BUFFER_SIZE 8192
#define USERNAME_MAX 32
#define TOKEN_LEN 64
#define SALT_LEN 32
#define SESSION_TIMEOUT 300
#define RATE_LIMIT_WINDOW 10
#define RATE_LIMIT_MAX 20
#define LOGIN_FAIL_WINDOW 60
#define LOGIN_FAIL_MAX 3
#define LOCKOUT_SECONDS 60


#define SID_FULL "1009"
#define LOG_FILE "server_IT24100919.log"
#define BASE_DIR "/srv/ie2102/IT24100919"

typedef struct {
    char username[USERNAME_MAX + 1];
    char token[TOKEN_LEN + 1];
    time_t last_activity;
    int logged_in;
} Session;

typedef struct {
    int count;
    time_t start_time;
} RateLimit;

typedef struct {
    int fail_count;
    time_t first_fail;
    time_t lockout_until;
} LoginAttempt;

static volatile sig_atomic_t server_running = 1;

void handle_sigint(int sig) {
    (void)sig;
    server_running = 0;
}

void handle_sigchld(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0) {}
}

void trim_newline(char *s) {
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r')) {
        s[len - 1] = '\0';
        len--;
    }
}

void make_dirs(const char *path) {
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

void current_time_str(char *buf, size_t size) {
    time_t now = time(NULL);
    struct tm tm_now;
    localtime_r(&now, &tm_now);
    strftime(buf, size, "%Y-%m-%d %H:%M:%S", &tm_now);
}

void write_audit_log(const char *client_ip, int client_port, pid_t pid,
                     const char *username, const char *command, const char *result) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (!fp) return;

    char ts[64];
    current_time_str(ts, sizeof(ts));
    fprintf(fp, "[%s] IP:%s PORT:%d PID:%d USER:%s CMD:%s RESULT:%s\n",
            ts,
            client_ip ? client_ip : "-",
            client_port,
            (int)pid,
            (username && strlen(username) > 0) ? username : "-",
            command ? command : "-",
            result ? result : "-"
    );
    fclose(fp);
}

int send_all(int sock, const char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(sock, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

int send_response(int sock, int ok, int code, const char *message) {
    char payload[1024];
    snprintf(payload, sizeof(payload), "%s %d SID:%s %s",
             ok ? "OK" : "ERR", code, SID_FULL, message);

    char framed[1200];
    snprintf(framed, sizeof(framed), "LEN:%zu\n%s", strlen(payload), payload);
    return send_all(sock, framed, strlen(framed));
}

int valid_username(const char *user) {
    size_t len = strlen(user);
    if (len < 3 || len > USERNAME_MAX) return 0;
    for (size_t i = 0; i < len; i++) {
        if (!(isalnum((unsigned char)user[i]) || user[i] == '_')) return 0;
    }
    return 1;
}

void random_hex(char *out, size_t bytes_needed) {
    unsigned char buf[64];
    FILE *fp = fopen("/dev/urandom", "rb");
    if (fp) {
        fread(buf, 1, bytes_needed, fp);
        fclose(fp);
    } else {
        srand((unsigned int)(time(NULL) ^ getpid()));
        for (size_t i = 0; i < bytes_needed; i++) buf[i] = rand() % 256;
    }
    for (size_t i = 0; i < bytes_needed; i++) {
        sprintf(out + (i * 2), "%02x", buf[i]);
    }
    out[bytes_needed * 2] = '\0';
}

int hash_password(const char *password, char *salt_out, size_t salt_sz,
                  char *hash_out, size_t hash_sz) {
    char salt_hex[SALT_LEN + 1];
    random_hex(salt_hex, SALT_LEN / 2);
    snprintf(salt_out, salt_sz, "$6$%s$", salt_hex);
    char *hashed = crypt(password, salt_out);
    if (!hashed) return -1;
    snprintf(hash_out, hash_sz, "%s", hashed);
    return 0;
}

int verify_password(const char *password, const char *stored_hash) {
    char *hashed = crypt(password, stored_hash);
    if (!hashed) return 0;
    return strcmp(hashed, stored_hash) == 0;
}

void user_file_path(const char *username, char *path, size_t size) {
    snprintf(path, size, "%s/%s/user.txt", BASE_DIR, username);
}

int register_user(const char *username, const char *password) {
    char dir[512], path[512], salt[128], hash[256];
    snprintf(dir, sizeof(dir), "%s/%s", BASE_DIR, username);
    user_file_path(username, path, sizeof(path));

    if (access(path, F_OK) == 0) return 1;

    make_dirs(dir);
    if (hash_password(password, salt, sizeof(salt), hash, sizeof(hash)) != 0) return -1;

    FILE *fp = fopen(path, "w");
    if (!fp) return -1;
    fprintf(fp, "username=%s\npassword_hash=%s\n", username, hash);
    fclose(fp);
    return 0;
}

int user_exists_and_password_ok(const char *username, const char *password) {
    char path[512], line[512], hash[512] = {0};
    user_file_path(username, path, sizeof(path));
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;

    while (fgets(line, sizeof(line), fp)) {
        trim_newline(line);
        if (strncmp(line, "password_hash=", 14) == 0) {
            snprintf(hash, sizeof(hash), "%s", line + 14);
        }
    }
    fclose(fp);
    if (hash[0] == '\0') return 0;
    return verify_password(password, hash);
}

int check_rate_limit(RateLimit *rl) {
    time_t now = time(NULL);
    if (rl->start_time == 0 || now - rl->start_time > RATE_LIMIT_WINDOW) {
        rl->start_time = now;
        rl->count = 1;
        return 1;
    }
    rl->count++;
    return rl->count <= RATE_LIMIT_MAX;
}

int login_locked(LoginAttempt *la) {
    time_t now = time(NULL);
    return la->lockout_until > now;
}

void login_fail(LoginAttempt *la) {
    time_t now = time(NULL);
    if (la->first_fail == 0 || now - la->first_fail > LOGIN_FAIL_WINDOW) {
        la->first_fail = now;
        la->fail_count = 1;
        la->lockout_until = 0;
        return;
    }
    la->fail_count++;
    if (la->fail_count >= LOGIN_FAIL_MAX) {
        la->lockout_until = now + LOCKOUT_SECONDS;
        la->fail_count = 0;
        la->first_fail = 0;
    }
}

void login_success(LoginAttempt *la) {
    la->fail_count = 0;
    la->first_fail = 0;
    la->lockout_until = 0;
}

int token_valid(Session *s, const char *token) {
    time_t now = time(NULL);
    if (!s->logged_in) return 0;
    if (strcmp(s->token, token) != 0) return 0;
    if (now - s->last_activity > SESSION_TIMEOUT) {
        s->logged_in = 0;
        s->username[0] = '\0';
        s->token[0] = '\0';
        return 0;
    }
    s->last_activity = now;
    return 1;
}

void issue_token(Session *s) {
    random_hex(s->token, TOKEN_LEN / 2);
    s->last_activity = time(NULL);
    s->logged_in = 1;
}

int process_command(const char *cmdline, Session *session, RateLimit *rl, LoginAttempt *la,
                    int client_sock, const char *client_ip, int client_port) {
    char copy[BUFFER_SIZE];
    char result[256] = "UNKNOWN";
    snprintf(copy, sizeof(copy), "%s", cmdline);

    if (!check_rate_limit(rl)) {
        send_response(client_sock, 0, 429, "Rate limit exceeded");
        write_audit_log(client_ip, client_port, getpid(), session->username, copy, "ERR 429");
        return 0;
    }

    char *saveptr = NULL;
    char *cmd = strtok_r(copy, " ", &saveptr);
    if (!cmd) {
        send_response(client_sock, 0, 400, "Empty command");
        write_audit_log(client_ip, client_port, getpid(), session->username, cmdline, "ERR 400");
        return 0;
    }

    if (strcmp(cmd, "REGISTER") == 0) {
        char *user = strtok_r(NULL, " ", &saveptr);
        char *pass = strtok_r(NULL, " ", &saveptr);
        if (!user || !pass) {
            strcpy(result, "ERR 400");
            send_response(client_sock, 0, 400, "Usage: REGISTER <user> <pass>");
        } else if (!valid_username(user)) {
            strcpy(result, "ERR 400");
            send_response(client_sock, 0, 400, "Invalid username");
        } else {
            int rc = register_user(user, pass);
            if (rc == 0) {
                strcpy(result, "OK 201");
                send_response(client_sock, 1, 201, "User registered");
            } else if (rc == 1) {
                strcpy(result, "ERR 409");
                send_response(client_sock, 0, 409, "User already exists");
            } else {
                strcpy(result, "ERR 500");
                send_response(client_sock, 0, 500, "Registration failed");
            }
        }
    } else if (strcmp(cmd, "LOGIN") == 0) {
        char *user = strtok_r(NULL, " ", &saveptr);
        char *pass = strtok_r(NULL, " ", &saveptr);
        if (!user || !pass) {
            strcpy(result, "ERR 400");
            send_response(client_sock, 0, 400, "Usage: LOGIN <user> <pass>");
        } else if (login_locked(la)) {
            strcpy(result, "ERR 423");
            send_response(client_sock, 0, 423, "Login temporarily locked");
        } else if (!user_exists_and_password_ok(user, pass)) {
            login_fail(la);
            strcpy(result, "ERR 401");
            send_response(client_sock, 0, 401, "Invalid username or password");
        } else {
            login_success(la);
            snprintf(session->username, sizeof(session->username), "%s", user);
            issue_token(session);
            char msg[256];
            snprintf(msg, sizeof(msg), "Login successful Token:%s", session->token);
            strcpy(result, "OK 200");
            send_response(client_sock, 1, 200, msg);
        }
    } else if (strcmp(cmd, "LOGOUT") == 0) {
        session->logged_in = 0;
        session->username[0] = '\0';
        session->token[0] = '\0';
        strcpy(result, "OK 200");
        send_response(client_sock, 1, 200, "Logged out");
    } else if (strcmp(cmd, "WHOAMI") == 0) {
        char *token = strtok_r(NULL, " ", &saveptr);
        if (!token || !token_valid(session, token)) {
            strcpy(result, "ERR 401");
            send_response(client_sock, 0, 401, "Invalid or expired token");
        } else {
            char msg[128];
            snprintf(msg, sizeof(msg), "Authenticated as %s", session->username);
            strcpy(result, "OK 200");
            send_response(client_sock, 1, 200, msg);
        }
    } else if (strcmp(cmd, "QUIT") == 0) {
        strcpy(result, "OK 200");
        send_response(client_sock, 1, 200, "Goodbye");
        write_audit_log(client_ip, client_port, getpid(), session->username, cmdline, result);
        return 1;
    } else {
        strcpy(result, "ERR 400");
        send_response(client_sock, 0, 400, "Unknown command");
    }

    write_audit_log(client_ip, client_port, getpid(), session->username, cmdline, result);
    return 0;
}

void handle_client(int client_sock, struct sockaddr_in client_addr) {
    char recv_buf[BUFFER_SIZE];
    char parse_buf[BUFFER_SIZE * 2];
    size_t parse_len = 0;
    Session session = {0};
    RateLimit rate_limit = {0};
    LoginAttempt login_attempt = {0};

    char client_ip[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    int client_port = ntohs(client_addr.sin_port);

    while (1) {
        ssize_t n = recv(client_sock, recv_buf, sizeof(recv_buf), 0);
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (parse_len + (size_t)n >= sizeof(parse_buf)) {
            send_response(client_sock, 0, 413, "Input buffer overflow");
            write_audit_log(client_ip, client_port, getpid(), session.username, "RAW", "ERR 413");
            break;
        }

        memcpy(parse_buf + parse_len, recv_buf, (size_t)n);
        parse_len += (size_t)n;
        parse_buf[parse_len] = '\0';

        while (1) {
            char *newline = memchr(parse_buf, '\n', parse_len);
            if (!newline) break;

            size_t header_len = (size_t)(newline - parse_buf);
            char header[128];
            if (header_len >= sizeof(header)) {
                send_response(client_sock, 0, 400, "Invalid length header");
                write_audit_log(client_ip, client_port, getpid(), session.username, "RAW", "ERR 400");
                goto cleanup;
            }

            memcpy(header, parse_buf, header_len);
            header[header_len] = '\0';

            if (strncmp(header, "LEN:", 4) != 0) {
                send_response(client_sock, 0, 400, "Missing LEN header");
                write_audit_log(client_ip, client_port, getpid(), session.username, "RAW", "ERR 400");
                goto cleanup;
            }

            char *endptr = NULL;
            long payload_len = strtol(header + 4, &endptr, 10);
            if (*endptr != '\0' || payload_len < 0) {
                send_response(client_sock, 0, 400, "Invalid length value");
                write_audit_log(client_ip, client_port, getpid(), session.username, "RAW", "ERR 400");
                goto cleanup;
            }
            if (payload_len > MAX_PAYLOAD) {
                send_response(client_sock, 0, 413, "Payload too large");
                write_audit_log(client_ip, client_port, getpid(), session.username, "RAW", "ERR 413");
                goto cleanup;
            }

            size_t total_needed = header_len + 1 + (size_t)payload_len;
            if (parse_len < total_needed) break;

            char payload[MAX_PAYLOAD + 1];
            memcpy(payload, newline + 1, (size_t)payload_len);
            payload[payload_len] = '\0';

            size_t remaining = parse_len - total_needed;
            memmove(parse_buf, parse_buf + total_needed, remaining);
            parse_len = remaining;
            parse_buf[parse_len] = '\0';

            if (process_command(payload, &session, &rate_limit, &login_attempt,
                                client_sock, client_ip, client_port)) {
                goto cleanup;
            }
        }
    }

cleanup:
    close(client_sock);
}

int main(void) {
    int server_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    make_dirs(BASE_DIR);

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);
    signal(SIGCHLD, handle_sigchld);

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_sock);
        return 1;
    }

    if (listen(server_sock, 20) < 0) {
        perror("listen");
        close(server_sock);
        return 1;
    }

    printf("Server running on port %d with SID:%s\n", PORT, SID_FULL);

    while (server_running) {
        int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            close(client_sock);
            continue;
        }

        if (pid == 0) {
            close(server_sock);
            handle_client(client_sock, client_addr);
            exit(0);
        } else {
            close(client_sock);
        }
    }

    close(server_sock);
    while (waitpid(-1, NULL, WNOHANG) > 0) {}
    return 0;
}
