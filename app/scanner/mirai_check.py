import logging

import paramiko

logger = logging.getLogger(__name__)

MIRAI_CREDS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("root", "root"),
    ("admin", "1234"),
    ("root", "vizxv"),
    ("admin", "password"),
    ("root", "password"),
    ("user", "user"),
    ("admin", "admin1234"),
    ("root", "root123"),
    ("support", "support"),
]


def check_mirai_ssh(host: str) -> tuple[bool, str, str]:
    for user, password in MIRAI_CREDS:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                host,
                username=user,
                password=password,
                timeout=3,
                banner_timeout=3,
                auth_timeout=3,
                look_for_keys=False,
                allow_agent=False,
            )
            client.close()
            logger.warning("Credencial Mirai aceptada en %s (user=%s)", host, user)
            return True, user, password
        except paramiko.AuthenticationException:
            pass
        except Exception as exc:
            logger.debug("SSH %s no accesible: %s", host, exc)
            break
        finally:
            try:
                client.close()
            except Exception:
                pass

    return False, "", ""
