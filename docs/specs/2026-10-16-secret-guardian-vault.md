# Secret Guardian: vault con proxy de inyección de credenciales

- **Fecha:** 2026-10-16
- **Estado:** borrador pendiente de revisión
- **Alcance de esta spec:** fase 1 (ver "Fases")

## 1. Propósito

Un vault de secretos propio, en Rust, para que agentes de IA hagan peticiones
autenticadas a APIs externas **sin poseer ni poder consultar nunca el secreto**.
El agente se autentica contra el vault con un token que lleva un rol; el vault
intercepta sus peticiones HTTP(S) e inyecta la credencial que ese rol tiene
permitida para ese destino.

Motivación: alternativa self-hosted a OneCLI sin depender de código ajeno ni de
un producto comercial. Es una herramienta **por operador y descentralizada**:
cada operador ejecuta su propia instancia, sin servidor central, sin multiusuario
y sin sincronización entre instancias.

### Criterios de éxito (fase 1)

1. Un agente con `HTTPS_PROXY` y la CA del vault hace `curl https://api.github.com/...`
   y la petición llega con `Authorization` inyectado, sin que el agente haya visto el valor.
2. Un token con rol `reviewer` (solo `GET`) recibe un rechazo al intentar `POST` al mismo host;
   un token `developer` lo consigue.
3. Ninguna ruta de la API, CLI ni web devuelve el valor de un secreto ya guardado.
4. La base de datos copiada sin la clave maestra no revela ningún secreto.
5. Se distribuye como un único binario y como imagen Docker.
6. Todo se puede configurar por CLI y por la web en `http://localhost:<puerto>`.

### Fuera de alcance (fase 1)

- Federación OIDC y tokens por agente (sí por máquina y rol).
- Sidecar / launcher `sg run` que guarda el token fuera del alcance del agente.
- Administración remota con login, multiusuario, alta disponibilidad.
- Inyección en body y firma de peticiones (AWS SigV4, HMAC).
- Redacción de secretos reflejados en la respuesta del destino.
- Proxy de protocolos distintos de HTTP/1.1 y HTTP/2 (websockets: solo se inyecta en el handshake).

## 2. Modelo de amenaza

| Amenaza | Mitigación |
|---|---|
| Agente (o prompt injection) intenta leer el secreto | La API nunca devuelve valores; el agente solo recibe respuestas del destino |
| Robo de la base de datos | Valores cifrados con AES-256-GCM; clave maestra fuera de la DB |
| Fuga de la clave de la CA | CA con name constraints: solo puede firmar para los dominios permitidos |
| Token del agente filtrado | TTL opcional, revocación inmediata, audit log por `jti`; ligado a máquina/rol |
| Página web maliciosa ataca la UI local | Solo `127.0.0.1`, validación de `Host`, sesión `HttpOnly`/`SameSite=Strict`, anti-CSRF |
| Agente usa el vault para llegar a hosts no previstos | Política por rol para hosts sin regla (ver 6.4) |

**Límite asumido:** un agente con acceso al proxy puede hacer peticiones a través
de él con los permisos de su rol; es inherente al modelo. La seguridad es que no
puede extraer el secreto y que las reglas acotan lo que puede hacer con él.

## 3. Arquitectura

Binario único, un proceso `tokio`, workspace Rust de crates con fronteras claras.

| Crate | Responsabilidad | Depende de |
|---|---|---|
| `core` | Cifrado, derivación de clave, almacén SQLite, esquema y migraciones | - |
| `policy` | Modelo de roles, secretos y reglas; matching host/path/método; construcción de la inyección | `core` |
| `auth` | Emisión y verificación de tokens (trait `TokenVerifier`), revocación | `core` |
| `ca` | Generación de la CA acotada, emisión y caché de certificados de hoja | `core` |
| `proxy` | Listener HTTP proxy, CONNECT, MITM TLS, inyección, reenvío, audit | `policy`, `auth`, `ca` |
| `admin` | API REST de administración (`axum`), sesiones web, assets estáticos | `policy`, `auth`, `ca` |
| `cli` | `clap`; habla con `admin` por socket Unix | - |
| `web/` | Frontend estático (HTML + JS sin build de Node), embebido con `rust-embed` | - |
| `bin` | Ensambla todo, `serve`, configuración | todos |

Cada crate debe poder entenderse y probarse sin leer los internos de los demás.
`TokenVerifier` es un trait para que OIDC sea un segundo validador en fases futuras
sin tocar `policy` ni `proxy`.

Bibliotecas previstas: `hyper`, `rustls`/`tokio-rustls`, `rcgen`, `axum`, `rusqlite`,
`aes-gcm`, `argon2`, `ed25519-dalek`, `clap`, `serde`, `tracing`. La elección final
se confirma en el plan.

## 4. Almacenamiento y cifrado

- SQLite, un único fichero (`vault.db`).
- **Clave maestra (KEK)**, de una de estas fuentes:
  - `--key-file` / `SG_KEY_FILE`: 32 bytes aleatorios codificados en base64 (Docker secret, permisos
    `0600`); se genera con `sg keygen --out <fichero>`.
  - `SG_MASTER_KEY`: la misma clave en base64.
  - `--passphrase`: se pide por terminal; Argon2id con sal guardada en la cabecera de la DB.
- Una **DEK** aleatoria de 32 bytes cifrada con la KEK vive en la DB; cifra todos los valores
  secretos, la clave privada de la CA y la clave de firma de tokens. Cambiar la passphrase o la
  clave maestra solo reescribe la DEK.
- AES-256-GCM, nonce aleatorio de 96 bits por valor, AAD = id del registro (evita mover
  valores entre filas).
- Si la KEK es incorrecta, el servidor no arranca y no revela cuál era el fallo concreto.
- Los valores descifrados solo existen en memoria durante la inyección y se limpian con `zeroize`.

### Esquema (resumen)

- `meta`: versión de esquema, sal Argon2, DEK cifrada.
- `secrets`: `id`, `name` (único), `value_enc`, `created_at`, `rotated_at`.
- `roles`: `name`, `unmatched_policy` (`passthrough` | `deny`).
- `rules`: `id`, `role`, `host_pattern`, `path_pattern`, `methods`, `injection_kind`
  (`header` | `query`), `target_name`, `template`, `secret_id`.
- `tokens`: `jti`, `machine`, `role`, `created_at`, `expires_at`, `revoked_at`, `token_hash`
  (solo para listar y revocar; el token en claro se muestra una única vez al crearlo).
- `audit`: `ts`, `jti`, `machine`, `role`, `host`, `method`, `path` (sin query string),
  `rule_id`, `decision`, `status`.
- `ca`: certificado, clave privada cifrada, dominios permitidos.

## 5. Autenticación de agentes

- Tokens JWT firmados con EdDSA. Claims: `iss`, `jti`, `sub` (= máquina), `role`, `iat`, `exp` opcional.
- La clave de firma se genera en el primer arranque y se guarda cifrada.
- El agente lo envía en `Proxy-Authorization`:
  - `Basic` con el token en la contraseña (compatible con `HTTPS_PROXY=http://x:TOKEN@host:puerto`).
  - `Bearer <token>`.
- Verificación sin lookup de DB salvo la comprobación de revocación por `jti`.
- Un token es válido para **un rol**. Una máquina puede tener varios tokens (p. ej. `developer`
  y `reviewer`). La etiqueta de máquina sirve para el audit log y la revocación en bloque.
- Sin token válido el proxy responde `407`; con token válido pero sin permiso, `403`.

## 6. Proxy e inyección

### 6.1 Flujo

1. El agente conecta al proxy (por defecto `127.0.0.1:8080`) y se autentica (5).
2. `CONNECT host:443`: se busca si el rol tiene alguna regla para `host`.
   - Hay regla: se responde `200`, se termina TLS con un certificado de hoja de `host` firmado
     por la CA, se lee la petición descifrada.
   - No hay regla: se aplica `unmatched_policy` del rol (6.4).
3. Por cada petición descifrada se evalúan las reglas del rol por orden de especificidad
   (host, path, método). Sin coincidencia exacta con método permitido: `403` y entrada en audit.
4. Se **elimina** cualquier cabecera o parámetro que el agente haya enviado con el mismo nombre
   que el destino de la inyección, y se inyecta el valor descifrado.
5. Se reenvía al destino real con TLS saliente (`rustls`, raíces del sistema más las CA añadidas
   con `--upstream-ca`, útil para servicios internos con CA privada), en streaming, sin almacenar
   cuerpos en memoria.
6. Se devuelve la respuesta tal cual y se escribe la entrada de audit.

### 6.2 Reglas

Una regla dice: *en este rol, para estos host/path/métodos, inyecta este secreto así*.

- `host_pattern`: exacto o wildcard de un nivel (`*.example.com`).
- `path_pattern`: prefijo o glob (`/repos/*`), por defecto `*`.
- `methods`: lista (`GET`, `POST`...), por defecto todos.
- Inyección `header`: `target_name` = nombre de cabecera, `template` p. ej. `Bearer {secret}` o
  `Basic {secret}`.
- Inyección `query`: `target_name` = parámetro, `template` exactamente `{secret}`. Las cabeceras de
  enmarcado y hop-by-hop (`Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Keep-Alive`,
  `TE`, `Trailer`, `Upgrade`, `Proxy-*`) no pueden ser destino de inyección.
- Las reglas comparan el **hostname** normalizado (minúsculas, sin punto final, sin puerto); el
  puerto no forma parte del patrón. Los hosts con forma de IP no admiten reglas.
- El path se normaliza antes de comparar (segmentos `.`/`..` resueltos, escapes de caracteres no
  reservados decodificados, `//` colapsado) y **se reenvía el path normalizado**: lo autorizado es
  lo enviado. Además, para reglas con path distinto de `*`, el
  juicio está **cerrado por construcción**: se leen todas las profundidades de decodificación
  porcentual (0 a 8 capas) y en ninguna puede haber un segmento punto (`.`, `..`, `...`, `.. `, `..+`: solo
  puntos, espacios, tabs o `+`) separando a la vez por `/`, `\`, `;`, `?` y `#`. Sin nada que resolver,
  ningún orden de operaciones del origen (decodificar, quitar `;params`, cortar en `?`/`#`, `\` como
  `/`, resolver puntos) puede salir del prefijo. Además, cada lectura debe empezar por el prefijo del
  patrón decodificado el mismo número de veces (igualdad exacta si el patrón no termina en `*`).
  No se puede juzgar, y las reglas con path responden `403` (solo `*` lo admite), un path con `%` mal
  formado, `%uXXXX`, UTF-8 inválido, NUL u otro carácter de control (C0, DEL), confusables Unicode
  de `.`, `/`, `\`, `?` o espacio, y espacios o caracteres invisibles no ASCII (p. ej. U+2025,
  U+FF0E, U+2215, U+FF1F, U+00A0, U+200B), más de 8 capas de codificación o más de 8 KiB.
  Consecuencia: `normalize_path` resuelve antes de juzgar los `..`/`%2e%2e` simples, así que
  `/repos/a/../b` pasa a `/repos/b` y se acepta, y `/repos/x/.` pasa a `/repos/x`; solo reciben `403`
  con reglas de path los segmentos punto que sobreviven a la normalización (`..;`, `..%2F`, `.. `,
  `...`, `..+`, formas doblemente codificadas) y los bytes no juzgables. Al crear la regla se
  rechazan los patrones que se ensanchan a sí mismos (segmentos punto, `;`, `\`, `?`, `#`, NUL,
  controles o confusables en cualquier profundidad de decodificación) y los que tienen un segmento
  terminado en `.` o espacio (un origen estilo Windows lo recortaría). Un prefijo que no termina en
  `/` (p. ej. `/v1*`) también casa con `/v1beta`, por diseño.
  Un `/` codificado solo se admite mientras permanezca dentro del prefijo de la regla.
- Por cada destino de inyección gana la regla más específica (host exacto; entre wildcards, el sufijo
  más largo, p. ej. `*.prod.corp.com` sobre `*.corp.com`; path exacto; patrón más largo). Si su
  método queda excluido, la respuesta es `403` en lugar de caer a una regla más amplia: la garantía
  es **por destino** (un destino distinto, p. ej. un parámetro de query, sí puede seguir aportando).
- Los valores de secreto no pueden contener CR, LF ni NUL; en inyección `query` el valor se codifica
  en porcentaje.

#### Suposiciones sobre el origen

El argumento de cierre descansa en estas suposiciones:

- **A1**: el origen decodifica en porcentaje solo `%HH` con hex ASCII, byte a byte, y luego lee
  UTF-8, cualquier número de rondas y en cualquier punto.
- **A2**: los separadores del origen son un subconjunto de `/ \ ; ? #`, y quitar `;params` elimina
  desde `;` hasta el siguiente `/` o el final.
- **A3**: los orígenes solo eliminan sufijos que empiezan en `?`/`#`, tramos desde `;` hasta el
  siguiente `/`, una `/` de `//`, y los puntos/espacios finales de un segmento.
- **A4**: las transformaciones de caracteres son solo ASCII (`\` a `/`, plegado de mayúsculas ASCII);
  la normalización Unicode y el `+` como espacio quedan cubiertos por la lista de caracteres
  prohibidos y por el conjunto de segmentos punto.
- **A5**: los segmentos punto solo se reconocen si están hechos de puntos, espacios, tabs y `+`.
- **A6**: el origen recibe exactamente la cadena que se juzgó (el proxy reenvía
  `normalize_path(raw)`; la query no interviene en el enrutado).

### 6.3 CA acotada

- La CA se crea en el primer arranque con **name constraints** (`permitted dNSName`) limitadas
  a los dominios registrados con `sg ca allow-domain <dominio>`. Un dominio permitido cubre sus
  subdominios.
- Sin dominios permitidos la CA se restringe al TLD reservado `invalid`, de modo que nunca queda
  sin restricciones. `allow-domain` rechaza TLDs y dominios de una sola etiqueta (salvo `localhost`).
  También excluye todas las direcciones IP (`0.0.0.0/0` y `::/0`), porque las restricciones DNS no
  limitan los SAN de tipo IP. `allow-domain` valida el nombre con las reglas DNS de webpki y comprueba
  con una hoja de prueba que el nuevo certificado sigue siendo válido para todos los dominios.
  `allow-domain` no consulta la Public Suffix List: el operador es responsable de no permitir sufijos
  públicos como `github.io`.
- Añadir un dominio fuera de lo permitido reemite el certificado de la CA **con la misma clave**
  y requiere que los agentes recarguen el certificado público. La UI y la CLI avisan.
- El certificado público se descarga con `sg ca export` o desde la web; la clave privada
  no sale nunca.
- Certificados de hoja de corta duración (24 h) y cacheados en memoria.
- Distribución a los agentes por variable de entorno (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`,
  `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`), no por el almacén del sistema.

### 6.4 Hosts sin regla

Por rol: `passthrough` (túnel TCP opaco, sin MITM ni inyección) o `deny` (`403`). Valor por
defecto propuesto: **`passthrough`**, para que los agentes sigan funcionando con hosts que no
necesitan credenciales. **Decisión a confirmar en la revisión.**

### 6.5 Limitaciones conocidas

- Herramientas con certificate pinning, Java (almacén propio) o binarios Go que ignoran las
  variables de entorno no funcionarán con el MITM.
- Si el destino refleja el secreto en su respuesta, el agente lo vería. Fuera de alcance.
- Websockets / upgrades: solo se inyecta en la petición de handshake.
- Inyección sobre HTTP en claro: se rechaza con `403` salvo que el host sea `localhost`; una regla
  nunca envía credenciales por una conexión sin TLS hacia Internet.

## 7. Administración

### 7.1 API

REST/JSON sobre `axum`. Recursos: `secrets`, `roles`, `rules`, `tokens`, `ca`, `audit`.

- **Regla fija:** ninguna operación devuelve `value`. `secrets` permite crear, rotar y borrar y
  devuelve solo metadatos.
- Dos listeners con la misma API y distinta autenticación:
  - **Socket Unix** (`$XDG_RUNTIME_DIR/secret-guardian.sock`, `0600`): usado por la CLI; la
    autenticación es el permiso del fichero.
  - **HTTP `127.0.0.1:<puerto>`** (por defecto 9090): usado por la web.
- Un bind no-loopback requiere la flag explícita `--admin-bind` y escribe un aviso; es el caso de
  Docker con puerto publicado solo a `127.0.0.1` del host. No hay login remoto en la fase 1.

### 7.2 Seguridad de la web local

- Validación estricta de `Host` (`localhost`, `127.0.0.1`) contra DNS rebinding.
- Al arrancar se imprime una URL de un solo uso con token de sesión; se canjea por cookie
  `HttpOnly`, `SameSite=Strict`, caducidad corta.
- Cabecera anti-CSRF obligatoria en las operaciones de escritura.
- `Content-Security-Policy` restrictiva; sin recursos de terceros.

### 7.3 CLI

```
sg serve [--key-file|--passphrase] [--proxy-bind] [--admin-bind] [--data-dir] [--socket] [--upstream-ca <pem>]
sg keygen   [--out <fichero>]
sg secret   add|rotate|rm|ls
sg role     add|rm|ls            (--unmatched passthrough|deny)
sg rule     add|rm|ls            (--role --host --path --methods --header|--query --template --secret)
sg token    create|revoke|ls     (--machine --role --ttl)
sg ca       export|allow-domain|status
sg audit    ls [--role --host --since]
```

`sg secret add` lee el valor de stdin o de un prompt sin eco, nunca de argumentos de línea
de comandos (evita que aparezca en el historial y en `ps`).

### 7.4 Web

Frontend estático sin build de Node, embebido en el binario. Pantallas: secretos (solo metadatos),
roles y reglas, tokens (el valor se muestra una vez), CA (descargar certificado, dominios
permitidos), audit log.

## 8. Errores y observabilidad

- Códigos del proxy: `407` sin token válido, `403` sin regla o método no permitido, `502` si falla
  el destino. Los mensajes no incluyen valores ni detalles de reglas.
- `tracing` estructurado; los valores secretos y los tokens nunca se registran.
- El audit log se escribe de forma síncrona antes de enviar el primer byte al agente.

## 9. Pruebas

- **Unitarias:** cifrado/descifrado y KEK errónea, derivación Argon2, matching de reglas
  (especificidad, wildcards, métodos), emisión/verificación/revocación de tokens, plantillas.
- **Integración:** proxy contra un servidor de prueba TLS local; comprobar inyección en header y
  query, sobrescritura de la cabecera enviada por el agente, `407`/`403`, streaming de cuerpos
  grandes, hosts sin regla en ambos modos.
- **CA:** un cliente `rustls` rechaza una hoja de un dominio fuera de las name constraints.
- **Seguridad:** ninguna respuesta de la API contiene el valor; un volcado de la DB no contiene
  el valor en claro; validación de `Host` y CSRF en la web.
- **E2E:** script con `curl` a través del proxy, con y sin CA, y rol `reviewer` frente a `developer`.

## 10. Fases

1. **Esta spec:** núcleo cifrado, CA acotada, proxy con inyección en header/query, tokens por
   (máquina, rol), reglas, audit, CLI y web local.
2. Sidecar / launcher `sg run` (el agente no ve el token).
3. Modo de administración remota con login (opt-in).
4. Federación OIDC como segundo `TokenVerifier` y tokens por agente.
5. Inyección en body y firmas (SigV4).

## 11. Requisitos previos y riesgos

- `cargo`/Rust no están instalados en esta máquina; el plan incluye instalar el toolchain (`rustup`).
- Gestión de name constraints: los clientes basados en OpenSSL y `rustls` las respetan, pero
  no todas las bibliotecas; se verifica en las pruebas con los clientes que más uses.
- El proxy MITM con HTTP/2 y streaming es la parte técnicamente más delicada; el plan la aísla
  en tareas propias con pruebas.
- El directorio no es un repositorio git todavía; hay que inicializarlo y trabajar en rama
  antes de implementar.

## 12. Decisiones pendientes de revisión

1. Política por defecto para hosts sin regla: `passthrough` (propuesto) o `deny`.
2. Puertos por defecto: proxy `8080`, web `9090`.
3. ~~Nombre~~ Resuelto en el plan: binario `sg`, paquete `secret-guardian` (`vault` chocaba con HashiCorp Vault).
