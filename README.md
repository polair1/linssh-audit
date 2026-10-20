# linssh-audit

Herramienta propia (estilo OpenVAS/Nessus pero enfocada en SSH grey-box/white-box sobre
Linux) para acelerar la parte mecánica de un pentest ya autorizado. Pensada para el
flujo usado en los engagements: VPN + credencial provista por el cliente →
enumeración → checklist → evidencia cruda en `pruebas/` → hallazgos confirmados a mano.

## ⚠️ Uso autorizado únicamente

Esta herramienta existe para acelerar trabajo de pentest **ya autorizado por escrito**
(engagement firmado, ROE/scope definido, credenciales entregadas por el cliente). No la
uses contra ningún sistema sobre el que no tengas autorización explícita. El autor no se
hace responsable de un uso fuera de ese contexto.

## Qué SÍ y qué NO hace (por diseño)

- ✅ Todos los comandos remotos son de **solo lectura**: `ls`, `cat`, `find`, `ss`/`netstat`,
  `ps`, `df`, `uname`, `dpkg -l`/`rpm -qa`, `systemctl is-active`/`list-units` (consulta de
  estado, nunca `start`/`stop`/`restart`), un `curl` GET al endpoint de metadata (IMDS).
- ✅ Login SSH con **un solo intento** por corrida, usando la credencial que vos le pasás —
  no es un brute-forcer de contraseñas.
- ✅ Verifica la clave del servidor contra `known_hosts` y rechaza servidores desconocidos
  o con una clave cambiada. Antes de correr la auditoría, agrega la clave del host por un
  canal confiable y verifica su fingerprint con el cliente; no confíes en una clave solo
  porque apareció en un escaneo.
- ❌ No ejecuta `rm`, `chmod`, `chown`, `kill`, `reboot`, `iptables`, ni ninguna escritura
  remota (`echo >`, `tee`, `sed -i`).
- ❌ No hace privilege escalation ni explota nada — solo enumera y detecta configuraciones
  candidatas a revisar.
- ❌ Los hallazgos candidatos de la Fase 3 **nunca se marcan como confirmados** — quedan en
  `hallazgos_PENDIENTE_REVISION.md`, explícitamente etiquetados como pendientes, para que
  vos los valides, les calcules el CVSS real (recomendado: librería `cvss` de RedHat) y
  decidas si entran a tu `hallazgos.md` final.
- ✅ El chequeo de IMDS hace solamente un `GET` sin token al endpoint base. No solicita
  tokens, roles, credenciales ni guarda contenido de metadata; un HTTP 200 se reporta
  únicamente como indicio de posible IMDSv1.
- ✅ La evidencia nueva se guarda con permisos restrictivos (POSIX `0700`/`0600`;
  Windows limita las ACL al usuario actual y `SYSTEM`) y no se sobrescriben corridas
  existentes: usa un `--outdir` nuevo para cada ejecución. Si el sistema no puede aplicar
  esos permisos, la herramienta informa el error y no continúa.
- ✅ Las evidencias registran códigos de salida y errores de ejecución; una comprobación
  que falla no se trata como un resultado positivo. El chequeo de paquetes solo informa
  nombres cuando detecta actualizaciones disponibles con un gestor reconocido; DNF/YUM
  usan solo la caché local para evitar refrescar metadatos en el servidor auditado.

## Instalación

```bash
pip install -r requirements.txt
```

El servidor SSH debe estar previamente registrado en el `known_hosts` de la cuenta local
que ejecuta la herramienta. Verifica la fingerprint por un canal confiable antes de
registrarlo.

## Uso

```bash
# Preflight + las 4 fases, con clave privada y chequeo de VPN antes de intentar SSH
python3 linssh_audit.py \
  --host 172.30.207.85 --port 3022 --user pt_ext \
  --key ~/.ssh/bodytech/pt_ext_key \
  --vpn-check 172.30.207.1 \
  --outdir ./Harvest_172.30.207.85

# Con password pedida de forma interactiva (no queda en el history)
python3 linssh_audit.py \
  --host 10.20.20.107 --user proyecto.cyber --ask-password \
  --outdir ./COMEDAPP04

# Solo preflight + recon, sin el checklist de vulns ni el borrador de reporte
python3 linssh_audit.py --host X --user Y --key ~/.ssh/id_rsa --phases 0,1,2 --outdir ./host_X
```

`--port` admite valores entre 1 y 65535; `--rate` debe ser finito y no negativo; las fases
deben ser números únicos entre 0 y 4. `--password` y `--ask-password` no se pueden usar a
la vez; se recomienda el modo interactivo para evitar dejar la contraseña en el historial.

## Fases

| Fase | Qué hace |
|---|---|
| 0 — Preflight | Ping/conectividad a un IP de la VPN (opcional), puerto SSH abierto, prueba la credencial real, revisa contexto de sudo. Si falla acá, corta antes de gastar tiempo en el resto. |
| 1 — Recon | SO, kernel, red, servicios escuchando, paquetes instalados. |
| 2 — Enumeración | usuarios/grupos, sudoers, cron, SUID/SGID, archivos/directorios mundo-escribibles, capabilities, permisos de archivos sensibles, `.env`/`.git` mundo-legibles, servicios systemd activos. |
| 3 — Checklist de vulns | Batería de chequeos de misconfiguración conocida (sshd hardening, IMDS, Docker socket, datastores locales sin auth, PwnKit/polkit, auditd, parches pendientes, PATH hijacking, secretos en logs, NTP). Cada hit se guarda como **candidato**, no como hallazgo confirmado. |
| 4 — Reporte | Vuelca un borrador `hallazgos_PENDIENTE_REVISION.md` con los candidatos de la Fase 3, cada uno apuntando a su archivo de evidencia cruda en `pruebas/`. |

## Salida

```
<outdir>/
  pruebas/
    01_preflight_vpn_ping.txt
    02_preflight_puerto_ssh.txt
    03_preflight_auth_ssh.txt
    ...   (1 archivo por prueba, con comando + salida cruda — mismo formato que ya usás)
  hallazgos_PENDIENTE_REVISION.md
```

## Qué falta / próximos pasos sugeridos

- Agregar más chequeos del checklist de securitycipher.com (api.md, cicd.md) cuando el
  host tenga ese rol.
- Sumar un modo `--diff` contra una corrida anterior para detectar cambios entre retest.
- Integrar el cálculo de CVSS real (librería `cvss`) directamente sobre los candidatos
  de la Fase 3 una vez que vos confirmás manualmente el vector.
# linssh-audit
