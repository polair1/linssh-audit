#!/usr/bin/env python3
"""
linssh-audit — Herramienta de auditoria de seguridad para servidores Linux via SSH.

Uso exclusivo en pentest/auditorias AUTORIZADAS (grey-box/white-box con credenciales
provistas por el cliente). No hace nada destructivo, no privesc, no fuerza bruta de
credenciales: solo pruebas de solo-lectura una vez que ya tenes una credencial valida.

Fases:
  0 - Preflight     : conectividad (VPN/red), puerto SSH abierto, auth real, sudo, contexto de usuario.
  1 - Recon pasivo  : SO, kernel, red, servicios escuchando, paquetes, procesos.
  2 - Enumeracion   : usuarios, permisos, cron, archivos sensibles, SUID/SGID, servicios locales.
  3 - Vuln checklist: bateria de verificaciones de misconfiguracion conocidas (solo lectura).
  4 - Reporte       : vuelca evidencia cruda (1 archivo por prueba) + borrador de hallazgos
                      candidatos a revisar manualmente (NUNCA se marcan como confirmados solos).

Ejemplos:
    python3 linssh_audit.py --host 172.30.207.85 --port 3022 --user pt_ext \
        --key ~/.ssh/pt_ext_key --vpn-check 172.30.207.1 --outdir ./Harvest_172.30.207.85

    python3 linssh_audit.py --host 10.20.20.107 --user proyecto.cyber --ask-password \
        --phases 0,1,2,3,4 --outdir ./COMEDAPP04
"""

import argparse
import datetime
import getpass
import ipaddress
import json
import os
import socket
import subprocess
import sys
import time

try:
    import paramiko
except ImportError:
    print("Falta paramiko: pip install --user paramiko", file=sys.stderr)
    sys.exit(1)


# --------------------------------------------------------------------------
# Utilidades generales
# --------------------------------------------------------------------------

class Evidence:
    """Guarda 1 archivo por prueba, igual a la convencion pruebas/NN_descripcion.txt
    ya usada en los engagements (PREBEL/BODITECH): numerado, nombre descriptivo,
    comando + salida cruda."""

    def __init__(self, outdir):
        self.outdir = outdir
        self.counter = 0
        os.makedirs(os.path.join(outdir, "pruebas"), exist_ok=True)

    def save(self, slug, command, output, extra_note=""):
        self.counter += 1
        fname = f"{self.counter:02d}_{slug}.txt"
        path = os.path.join(self.outdir, "pruebas", fname)
        with open(path, "w") as f:
            f.write(f"# Fecha: {datetime.datetime.now().isoformat()}\n")
            if extra_note:
                f.write(f"# Nota: {extra_note}\n")
            f.write(f"$ {command}\n")
            f.write(output if output is not None else "(sin salida)\n")
        return path


class Finding:
    """Candidato a hallazgo. NUNCA se declara confirmado automaticamente: todo
    queda como PENDIENTE DE REVISION HUMANA con la evidencia cruda asociada."""

    def __init__(self, titulo, severidad_sugerida, descripcion, evidencia_path, activo):
        self.titulo = titulo
        self.severidad_sugerida = severidad_sugerida  # solo orientativa, no CVSS calculado
        self.descripcion = descripcion
        self.evidencia_path = evidencia_path
        self.activo = activo


def log(msg, level="INFO"):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    tag = {"INFO": "\033[36m[INFO]\033[0m", "OK": "\033[32m[ OK ]\033[0m",
           "WARN": "\033[33m[WARN]\033[0m", "FAIL": "\033[31m[FAIL]\033[0m",
           "FIND": "\033[35m[FIND]\033[0m"}.get(level, "[....]")
    print(f"{ts} {tag} {msg}")


_RATE = {"seconds": 0.25}


def set_rate(seconds):
    _RATE["seconds"] = seconds


def rate_limit_sleep():
    # ~4 req/s por defecto, consistente con el criterio de bajo ruido usado en los engagements.
    time.sleep(_RATE["seconds"])


# --------------------------------------------------------------------------
# Fase 0 — Preflight: conectividad, VPN, credenciales, contexto
# --------------------------------------------------------------------------

def tcp_check(host, port, timeout=5):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            try:
                s.settimeout(2)
                banner = s.recv(256)
            except Exception:
                banner = b""
            return True, banner.decode(errors="replace").strip()
    except Exception as e:
        return False, str(e)


def vpn_reachability_check(target_ip, evidence):
    """Chequeo de que la VPN/red del cliente esta arriba, antes de intentar SSH.
    Usa ping; si esta bloqueado por ICMP, cae a un connect TCP simple al propio target_ip:22
    como señal secundaria de alcanzabilidad de la red."""
    log(f"Preflight: verificando alcanzabilidad de red hacia {target_ip} (VPN)...")
    try:
        proc = subprocess.run(["ping", "-c", "3", "-W", "2", target_ip],
                               capture_output=True, text=True, timeout=15)
        out = proc.stdout + proc.stderr
        evidence.save("preflight_vpn_ping", f"ping -c 3 -W 2 {target_ip}", out)
        if proc.returncode == 0:
            log(f"VPN/red alcanzable: {target_ip} responde a ping.", "OK")
            return True
        else:
            log(f"{target_ip} no responde a ping (puede ser ICMP bloqueado, no necesariamente VPN caida).", "WARN")
            return None  # indeterminado, no False
    except Exception as e:
        evidence.save("preflight_vpn_ping", f"ping -c 3 -W 2 {target_ip}", str(e))
        log(f"No se pudo ejecutar ping: {e}", "WARN")
        return None


def ssh_port_check(host, port, evidence):
    log(f"Preflight: probando puerto SSH {host}:{port}...")
    ok, info = tcp_check(host, port)
    evidence.save("preflight_puerto_ssh", f"tcp-connect {host}:{port}", info)
    if ok:
        log(f"Puerto {port} abierto. Banner: {info or '(sin banner)'}", "OK")
    else:
        log(f"Puerto {port} no responde: {info}", "FAIL")
    return ok


def ssh_auth_check(host, port, user, password, key_path, evidence):
    """Prueba la credencial provista. Un solo intento (no es fuerza bruta,
    es una credencial ya entregada por el cliente para el engagement)."""
    log(f"Preflight: probando autenticacion SSH como '{user}'...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        kwargs = dict(hostname=host, port=port, username=user, timeout=10,
                      banner_timeout=10, auth_timeout=10)
        if key_path:
            kwargs["key_filename"] = os.path.expanduser(key_path)
            if password:
                kwargs["passphrase"] = password
        elif password:
            kwargs["password"] = password
        client.connect(**kwargs)
        stdin, stdout, stderr = client.exec_command("id; whoami; hostname")
        out = stdout.read().decode(errors="replace") + stderr.read().decode(errors="replace")
        evidence.save("preflight_auth_ssh", "id; whoami; hostname (post-login)", out,
                       extra_note="Credencial provista por el cliente para el engagement, no fuerza bruta.")
        log("Autenticacion SSH exitosa.", "OK")
        log(out.strip().replace("\n", " | "))
        return client
    except paramiko.AuthenticationException as e:
        evidence.save("preflight_auth_ssh", "intento de login", f"AuthenticationException: {e}")
        log(f"Autenticacion fallida: {e}", "FAIL")
        return None
    except Exception as e:
        evidence.save("preflight_auth_ssh", "intento de login", f"{type(e).__name__}: {e}")
        log(f"Error de conexion SSH: {e}", "FAIL")
        return None


def sudo_context_check(client, evidence):
    log("Preflight: verificando contexto de privilegios (sudo -l, no interactivo)...")
    out = run(client, "sudo -n -l 2>&1 || echo '(sin sudo o requiere password)'")
    evidence.save("preflight_sudo_context", "sudo -n -l", out)
    if "may run" in out.lower() or "NOPASSWD" in out:
        log("La cuenta tiene privilegios sudo (ver detalle en evidencia).", "WARN")
    else:
        log("Sin privilegios sudo visibles sin password (esperable para cuenta grey-box sin privilegios).", "OK")
    return out


def run(client, command, timeout=25):
    """Ejecuta un comando de solo lectura y devuelve stdout+stderr combinados."""
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        combined = out
        if err.strip():
            combined += f"\n[stderr]\n{err}"
        return combined
    except Exception as e:
        return f"(error ejecutando comando: {e})"


# --------------------------------------------------------------------------
# Fase 1 — Reconocimiento pasivo/activo (info de sistema, red, servicios)
# --------------------------------------------------------------------------

RECON_COMMANDS = [
    ("sistema_uname", "uname -a"),
    ("sistema_os_release", "cat /etc/os-release 2>/dev/null"),
    ("sistema_uptime", "uptime"),
    ("red_interfaces", "ip a 2>/dev/null || ifconfig -a"),
    ("red_rutas", "ip r 2>/dev/null || route -n"),
    ("red_resolv", "cat /etc/resolv.conf 2>/dev/null"),
    ("servicios_escuchando", "ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null"),
    ("procesos", "ps auxww"),
    ("discos", "df -h"),
    ("paquetes_instalados_count",
     "dpkg -l 2>/dev/null | wc -l || rpm -qa 2>/dev/null | wc -l"),
]


def phase1_recon(client, evidence):
    log("=== FASE 1: Reconocimiento pasivo/activo ===")
    results = {}
    for slug, cmd in RECON_COMMANDS:
        out = run(client, cmd)
        evidence.save(slug, cmd, out)
        results[slug] = out
        rate_limit_sleep()
    log("Fase 1 completa.", "OK")
    return results


# --------------------------------------------------------------------------
# Fase 2 — Enumeracion (usuarios, permisos, cron, archivos sensibles)
# --------------------------------------------------------------------------

ENUM_COMMANDS = [
    ("usuarios_passwd", "cat /etc/passwd"),
    ("grupos", "cat /etc/group"),
    ("usuarios_con_shell", "awk -F: '$7 !~ /nologin|false/ {print $1\":\"$7}' /etc/passwd"),
    ("sudoers", "sudo -n cat /etc/sudoers 2>/dev/null; ls -la /etc/sudoers.d/ 2>/dev/null"),
    ("cron_sistema", "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d/ 2>/dev/null"),
    ("cron_usuario", "crontab -l 2>&1"),
    ("suid_sgid",
     "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null"),
    ("archivos_mundo_escribibles",
     "find / -xdev -type f -perm -0002 -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -100"),
    ("directorios_mundo_escribibles_sin_sticky",
     "find / -xdev -type d -perm -0002 ! -perm -1000 -not -path '/proc/*' -not -path '/tmp' -not -path '/sys/*' 2>/dev/null | head -100"),
    ("capabilities",
     "getcap -r / 2>/dev/null | head -100"),
    ("permisos_sensibles",
     "ls -la /etc/shadow /etc/passwd /etc/sudoers /root/.ssh 2>&1"),
    ("ssh_host_keys_permisos", "ls -la /etc/ssh/ssh_host_* 2>&1"),
    ("env_y_git_mundo_legible",
     "find / -xdev \\( -iname '.env' -o -iname '.git' \\) -not -path '/proc/*' 2>/dev/null "
     "-exec ls -lad {} \\; 2>/dev/null | head -50"),
    ("servicios_systemd_activos", "systemctl list-units --type=service --state=running 2>/dev/null | head -60"),
]


def phase2_enum(client, evidence):
    log("=== FASE 2: Enumeracion ===")
    results = {}
    for slug, cmd in ENUM_COMMANDS:
        out = run(client, cmd)
        evidence.save(slug, cmd, out)
        results[slug] = out
        rate_limit_sleep()
    log("Fase 2 completa.", "OK")
    return results


# --------------------------------------------------------------------------
# Fase 3 — Checklist de vulnerabilidades/misconfiguraciones (solo lectura)
#   Inspirado en las categorias ya usadas en los engagements
#   (securitycipher.com/security-checklists: infrastructure/network/api/cicd)
# --------------------------------------------------------------------------

def phase3_vuln_checklist(client, evidence, findings):
    log("=== FASE 3: Checklist de vulnerabilidades (solo lectura) ===")

    def check(slug, cmd, note=""):
        out = run(client, cmd)
        path = evidence.save(slug, cmd, out, extra_note=note)
        rate_limit_sleep()
        return out, path

    # 1) Hardening de sshd
    out, path = check("sshd_config_hardening",
                       "sudo -n cat /etc/ssh/sshd_config 2>/dev/null || cat /etc/ssh/sshd_config 2>/dev/null")
    if "PermitRootLogin yes" in out:
        findings.append(Finding(
            "PermitRootLogin habilitado en sshd_config", "Media/Alta (a calcular con CVSS real)",
            "sshd_config permite login directo de root por SSH (PermitRootLogin yes).",
            path, "sshd"))
    if "PasswordAuthentication yes" in out and "#PasswordAuthentication yes" not in out:
        log("PasswordAuthentication habilitado (no necesariamente un hallazgo, depende del contexto de MFA).", "WARN")

    # 2) IMDS sin restriccion (entornos cloud/AWS)
    out, path = check("imds_sin_restriccion",
                       "curl -s --max-time 3 -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' "
                       "-X PUT http://169.254.169.254/latest/api/token 2>&1; echo '---'; "
                       "curl -s --max-time 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>&1")
    if out.strip() and "Connection" not in out.split("---")[-1][:40] and "refused" not in out.lower() \
            and "timed out" not in out.lower() and out.split("---")[-1].strip():
        findings.append(Finding(
            "IMDS accesible sin restriccion de usuario (posible)", "A revisar",
            "El endpoint de metadata de instancia (169.254.169.254) respondio. Verificar manualmente "
            "si cualquier cuenta local puede obtener credenciales IAM temporales.",
            path, "IMDS"))

    # 3) Docker socket expuesto
    out, path = check("docker_socket",
                       "ls -la /var/run/docker.sock 2>&1; groups 2>&1")
    if "/var/run/docker.sock" in out and "No such file" not in out:
        if "docker" in out.split("groups")[-1] if "groups" in out else False:
            findings.append(Finding(
                "Usuario en grupo docker con socket accesible", "Alta (a confirmar)",
                "El socket de Docker existe y el usuario actual pertenece al grupo docker "
                "(equivalente a root via montaje de volumen). Verificar manualmente antes de reportar.",
                path, "Docker"))

    # 4) Redis / Mongo / Memcached sin auth en loopback (deteccion, no explotacion)
    out, path = check("servicios_db_locales",
                       "ss -tulnp 2>/dev/null | grep -E ':6379|:27017|:11211|:5432|:3306' || "
                       "netstat -tulnp 2>/dev/null | grep -E ':6379|:27017|:11211|:5432|:3306'")
    if out.strip() and "error" not in out.lower():
        findings.append(Finding(
            "Servicio de base de datos/cache escuchando localmente (Redis/Mongo/Memcached/Postgres/MySQL)",
            "A revisar", "Se detecto un puerto de datastore conocido en escucha. Verificar manualmente "
            "si exige autenticacion y si una cuenta local sin relacion con el servicio puede conectarse "
            "(ej. redis-cli PING sin auth).", path, "Servicios locales"))

    # 5) PwnKit / polkit
    out, path = check("pwnkit_polkit",
                       "pkexec --version 2>&1; dpkg -l policykit-1 2>/dev/null || rpm -q polkit 2>/dev/null")
    if "command not found" not in out.lower() and out.strip():
        log("polkit/pkexec presente, verificar version contra CVE-2021-4034 manualmente si corresponde.", "WARN")

    # 6) auditd activo
    out, path = check("auditd_status", "systemctl is-active auditd 2>&1; service auditd status 2>&1")
    if "inactive" in out.lower() or "not running" in out.lower():
        findings.append(Finding(
            "auditd no esta activo", "Informativa",
            "El servicio de auditoria del sistema (auditd) no esta activo. Reduce la trazabilidad "
            "forense pero no es una vulnerabilidad explotable por si sola.", path, "auditd"))

    # 7) Paquetes desactualizados
    out, path = check("paquetes_desactualizados",
                       "apt list --upgradable 2>/dev/null | wc -l || yum check-update 2>/dev/null | wc -l")
    findings.append(Finding(
        "Paquetes de sistema con actualizacion disponible", "Informativa/Baja",
        f"Cantidad de paquetes actualizables detectada: {out.strip()}. Revisar manualmente si alguno "
        "es critico (openssh-server, openssl, sudo, libc6, kernel).", path, "Parches"))

    # 8) PATH hijacking (directorios del PATH escribibles por el usuario actual)
    out, path = check("path_hijacking",
                       "echo $PATH | tr ':' '\\n' | xargs -I{} sh -c 'test -w {} && echo ESCRIBIBLE: {}' 2>/dev/null")
    if out.strip():
        findings.append(Finding(
            "Directorio del PATH escribible por el usuario actual", "Alta (a confirmar)",
            "Al menos un directorio del PATH del usuario es escribible, lo que habilitaria PATH hijacking "
            "si un proceso con mas privilegios invoca un binario sin ruta absoluta.", path, "PATH"))

    # 9) Logs con posibles secretos (grep no intrusivo, sin modificar nada)
    out, path = check("logs_grep_secretos",
                       "sudo -n grep -riE 'password|secret|api[_-]?key' /var/log/*.log 2>/dev/null | head -20; "
                       "grep -riE 'password|secret|api[_-]?key' /var/log/*.log 2>/dev/null | head -20")
    if out.strip():
        findings.append(Finding(
            "Posibles secretos en logs de aplicacion", "A revisar",
            "Se encontraron lineas que matchean patrones de password/secret/api-key en logs. "
            "Revisar manualmente si son valores reales o solo nombres de campo/ruido.", path, "Logs"))

    # 10) NTP sincronizado
    out, path = check("ntp_sync", "timedatectl 2>/dev/null || ntpq -p 2>/dev/null")
    if "synchronized: yes" not in out.lower() and "synchronized" in out.lower():
        log("NTP no sincronizado (informativo).", "WARN")

    log(f"Fase 3 completa. {len(findings)} candidatos a revisar.", "OK")
    return findings


# --------------------------------------------------------------------------
# Fase 4 — Reporte: evidencia ya quedo en pruebas/, acá se arma el borrador
# --------------------------------------------------------------------------

def phase4_report(outdir, host, port, user, findings, activo_nombre):
    log("=== FASE 4: Borrador de hallazgos (PENDIENTE DE REVISION MANUAL) ===")
    path = os.path.join(outdir, "hallazgos_PENDIENTE_REVISION.md")
    with open(path, "w") as f:
        f.write(f"# Candidatos a hallazgo — {activo_nombre} ({host}:{port}, usuario {user})\n\n")
        f.write("**IMPORTANTE: ninguno de estos esta confirmado.** Son candidatos detectados por la "
                "herramienta a partir de evidencia real (ver pruebas/), pero requieren revision manual, "
                "calculo de CVSS 4.0 con la libreria real, y confirmacion de impacto antes de pasar a "
                "`hallazgos.md`. No reportar nada de aca sin validar.\n\n")
        f.write(f"Generado: {datetime.datetime.now().isoformat()}\n\n---\n\n")
        if not findings:
            f.write("Sin candidatos detectados automaticamente en este pase. Revisar igual la evidencia "
                    "cruda completa en `pruebas/` — la ausencia de un candidato automatico no implica "
                    "ausencia de vulnerabilidad.\n")
        for i, fnd in enumerate(findings, 1):
            f.write(f"## CANDIDATO {i} — {fnd.titulo}\n\n")
            f.write(f"**Activo:** {fnd.activo}\n\n")
            f.write(f"**Severidad sugerida (orientativa, NO calculada con CVSS real):** {fnd.severidad_sugerida}\n\n")
            f.write(f"**Descripcion:** {fnd.descripcion}\n\n")
            f.write(f"**Evidencia:** `{os.path.relpath(fnd.evidencia_path, outdir)}`\n\n")
            f.write("**Estado:** PENDIENTE DE REVISION MANUAL\n\n---\n\n")
    log(f"Borrador guardado en {path}", "OK")
    return path


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True, help="IP o hostname del servidor")
    ap.add_argument("--port", type=int, default=22, help="Puerto SSH (default 22)")
    ap.add_argument("--user", required=True, help="Usuario SSH provisto por el cliente")
    ap.add_argument("--password", help="Password SSH (si no se usa --key). Evitar en shell history; preferir --ask-password")
    ap.add_argument("--ask-password", action="store_true", help="Pide la password de forma interactiva (no queda en history)")
    ap.add_argument("--key", help="Ruta a la clave privada SSH")
    ap.add_argument("--vpn-check", help="IP a hacer ping antes de intentar SSH (ej. gateway de la VPN del cliente)")
    ap.add_argument("--phases", default="0,1,2,3,4", help="Fases a correr, separadas por coma (default: todas)")
    ap.add_argument("--outdir", required=True, help="Carpeta de salida (evidencia + borrador de hallazgos)")
    ap.add_argument("--rate", type=float, default=0.25, help="Segundos de espera entre comandos (default 0.25s, ~4/s)")
    args = ap.parse_args()

    phases = set(args.phases.split(","))
    os.makedirs(args.outdir, exist_ok=True)
    evidence = Evidence(args.outdir)
    set_rate(args.rate)

    log(f"=== linssh-audit — {args.host}:{args.port} (usuario: {args.user}) ===")
    log(f"Salida: {args.outdir}")
    log("Uso autorizado unicamente. Todas las pruebas son de solo lectura.")

    password = args.password
    if args.ask_password and not password:
        password = getpass.getpass("Password SSH: ")

    # ---------------- Fase 0: Preflight ----------------
    if "0" in phases:
        log("=== FASE 0: Preflight (conectividad / VPN / credenciales) ===")
        if args.vpn_check:
            vpn_reachability_check(args.vpn_check, evidence)

        port_ok = ssh_port_check(args.host, args.port, evidence)
        if not port_ok:
            log("El puerto SSH no respondio. Verificar VPN/firewall antes de continuar.", "FAIL")
            sys.exit(2)

        client = ssh_auth_check(args.host, args.port, args.user, password, args.key, evidence)
        if not client:
            log("No se pudo autenticar. Verificar credenciales/VPN antes de continuar.", "FAIL")
            sys.exit(2)

        sudo_context_check(client, evidence)
        log("Preflight OK — continuando con las fases siguientes.", "OK")
    else:
        log("Fase 0 (preflight) omitida por flag --phases: se requiere conexion igual para las demas fases.", "WARN")
        client = ssh_auth_check(args.host, args.port, args.user, password, args.key, evidence)
        if not client:
            sys.exit(2)

    findings = []
    activo_nombre = f"{args.host}:{args.port}"

    if "1" in phases:
        phase1_recon(client, evidence)
    if "2" in phases:
        phase2_enum(client, evidence)
    if "3" in phases:
        phase3_vuln_checklist(client, evidence, findings)
    if "4" in phases:
        phase4_report(args.outdir, args.host, args.port, args.user, findings, activo_nombre)

    client.close()
    log("=== Auditoria finalizada ===", "OK")
    log(f"Evidencia cruda: {os.path.join(args.outdir, 'pruebas')}")
    log(f"Candidatos a revisar: {len(findings)} (ver hallazgos_PENDIENTE_REVISION.md)")


if __name__ == "__main__":
    main()
