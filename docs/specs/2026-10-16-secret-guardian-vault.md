# Secret Guardian: vault con proxy de inyección de credenciales

- **Fecha:** 2026-10-16
- **Estado:** borrador pendiente de revisión
- **Alcance de esta spec:** fase 1 (ver "Fases")
- **Enmienda 2026-10-19:** todo secreto nace con al menos una regla y la CA se deriva de las reglas
  (§4, §6.3, §7.3–7.5); autenticación por proceso registrada como fase 2b (§5, §10).

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
| Página web maliciosa ataca la UI local | Solo `127.0.0.1`, validación de `Host` y `Origin`, sesión en cabecera `Authorization: Bearer` (no en cookie), token de login en el fragmento de la URL |
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
  secretos, la clave privada de la CA y la clave de firma de tokens. El diseño permite re-envolver
  la DEK con una KEK nueva sin recifrar los valores, pero la rotación de passphrase o clave
  maestra **no está implementada en la fase 1** (queda para una fase posterior).
- AES-256-GCM, nonce aleatorio de 96 bits por valor, AAD = cadena de propósito, no solo el
  id del registro: `sg:dek`, `secret:{id}`, `sg:token-signing-key`, `sg:ca-key` (evita mover
  valores entre filas o entre usos).
- Si la KEK es incorrecta, el servidor no arranca y no revela cuál era el fallo concreto.
- Los valores descifrados solo existen en memoria durante la inyección y se limpian con `zeroize` en la medida de lo posible (*best effort*: las copias dentro de `hyper`/`http` no se borran).

### Esquema (resumen)

- `meta`: versión de esquema, `kdf`, sal Argon2, DEK cifrada, `token_signing_key`.
- `secrets`: `id`, `name` (único), `value_enc`, `created_at`, `rotated_at`. Invariante (§7.5): todo
  secreto tiene al menos una fila en `rules`.
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
- **Aislamiento entre agentes en una misma máquina.** El token es una identidad, no una credencial:
  quien lo roba no obtiene ningún secreto, pero sí los permisos de su rol mientras siga vivo. Dos
  agentes con el mismo usuario del sistema pueden leerse el entorno (`/proc/<pid>/environ`), así que
  el aislamiento real exige contenedores, usuarios o namespaces distintos; con el mismo usuario solo se
  reduce el daño (token solo en el entorno de su proceso, TTL cortos, revocación, audit). Se documenta
  en `docs/security-model.md`. La fase 2b elimina el token como secreto (§10).

## 6. Proxy e inyección

### 6.1 Flujo

1. El agente conecta al proxy (por defecto `127.0.0.1:8080`) y se autentica (5).
2. `CONNECT host:443`: se busca si el rol tiene alguna regla para `host`.
   - Hay regla: se responde `200`, se termina TLS con un certificado de hoja de `host` firmado
     por la CA, se lee la petición descifrada.
   - No hay regla: se aplica `unmatched_policy` del rol (6.4). La librería no tiene valor por
     defecto; la CLI `sg role add` usa `--unmatched passthrough` por defecto.
3. Por cada petición descifrada se evalúan las reglas del rol por orden de especificidad
   (host, path, método). Sin coincidencia exacta con método permitido: `403` y entrada en audit.
4. Se **elimina** cualquier cabecera o parámetro que el agente haya enviado con el mismo nombre
   que el destino de la inyección, y se inyecta el valor descifrado.
5. Se reenvía al destino real con TLS saliente (`rustls`, raíces del sistema más las CA añadidas
   con `--upstream-ca`, útil para servicios internos con CA privada), en streaming, sin almacenar
   cuerpos en memoria.
6. Se devuelve la respuesta tal cual. La entrada de audit se escribe cuando se ha recibido la
   cabecera de respuesta del destino y antes de devolverla al agente (en las peticiones que el
   proxy rechaza, antes de devolver el rechazo).
7. Una petición `http://` en forma absoluta (sin CONNECT) **nunca recibe una credencial inyectada**:
   si el host tiene reglas para el rol se responde siempre `403` (decisión `plaintext-refused`), sin
   excepciones (tampoco `localhost`, ni con puerto explícito); un host sin reglas sigue la política
   del rol (6.4) y, bajo `passthrough`, se reenvía sin inyección.
8. Un CONNECT o una petición de forma absoluta mal formados (`400`) de un agente autenticado se
   auditan con decisión `bad-request` y la identidad; la autenticación fallida (`407`) no escribe nada, salvo un token con firma válida pero revocado o caducado (ver §8).

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
  reservados decodificados, `//` colapsado). Si alguna regla del rol que casa con el host tiene un
  path distinto de `*`, **se reenvía el path normalizado**: lo autorizado es lo enviado. Si ninguna
  regla que casa con el host tiene path restringido (hosts sin reglas bajo un rol `passthrough`, o
  solo con reglas `*`), no se juzga ningún path y se reenvía el **path original** del agente tal cual
  (más la query original), porque algunos orígenes (claves estilo S3, `/fetch/https://otro`)
  distinguen `//` o los escapes. Además, para reglas con path distinto de `*`, el
  juicio está **cerrado por construcción**: se leen todas las profundidades de decodificación
  porcentual (0 a 8 capas) y en ninguna puede haber un segmento punto (`.`, `..`, `...`, `.. `, `..+`: solo
  puntos, espacios, tabs o `+`) separando a la vez por `/`, `\`, `;`, `?` y `#`. Sin nada que resolver,
  ningún orden de operaciones del origen (decodificar, quitar `;params`, cortar en `?`/`#`, `\` como
  `/`, resolver puntos) puede salir del prefijo. Además, cada lectura debe empezar por el prefijo del
  patrón decodificado el mismo número de veces (igualdad exacta si el patrón no termina en `*`).
  No se puede juzgar, y las reglas con path responden `403` (solo `*` lo admite), un path con `%` mal
  formado, `%uXXXX`, UTF-8 inválido, NUL u otro carácter de control (C0, DEL), **cualquier carácter
  no ASCII en cualquier profundidad de decodificación** (lista blanca: se juzga solo si todas las
  lecturas son ASCII; así no hace falta enumerar confusables como U+2025, U+FF0E, U+2215, U+FF1F,
  U+FE30, U+FE19, U+2100..U+2106 o U+200B, y letras con acento, CJK o emoji tampoco son juzgables),
  más de 8 capas de codificación o más de 8 KiB. Falla cerrado: para esos paths usa una regla con
  path `*` o codifica la ruta de otro modo (ASCII).
  Consecuencia: `normalize_path` resuelve antes de juzgar los `..`/`%2e%2e` simples, así que
  `/repos/a/../b` pasa a `/repos/b` y se acepta, y `/repos/x/.` pasa a `/repos/x`; solo reciben `403`
  con reglas de path los segmentos punto que sobreviven a la normalización (`..;`, `..%2F`, `.. `,
  `...`, `..+`, formas doblemente codificadas) y los bytes no juzgables. Al crear la regla se
  rechazan los patrones que se ensanchan a sí mismos (segmentos punto, `;`, `\`, `?`, `#`, NUL,
  controles o cualquier carácter no ASCII en cualquier profundidad de decodificación) y los que tienen un segmento
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
  la normalización Unicode queda cubierta por la lista blanca ASCII (cualquier carácter no ASCII hace
  el path no juzgable) y el `+` como espacio por el conjunto de segmentos punto.
- **A5**: los segmentos punto solo se reconocen si están hechos de puntos, espacios, tabs y `+`.
- **A6**: cuando interviene una regla con path restringido, el origen recibe exactamente la cadena que
  se juzgó (el proxy reenvía `normalize_path(raw)`; la query no interviene en el enrutado); si no
  interviene ninguna, no se juzga ningún path y el origen recibe el path original.
- **A7**: el proxy elimina las cabeceras de override de enrutado y de reenvío (`X-HTTP-Method-Override`,
  `X-Original-URL`, `X-Original-URI`, `X-Forwarded-*`, `Forwarded`, `Via`, `X-Client-IP`,
  `True-Client-IP`, `CF-Connecting-IP`, `X-Cluster-Client-IP`...) comparando el nombre normalizado
  (minúsculas, `_` equivale a `-`: `X_HTTP_METHOD_OVERRIDE` también se elimina; `Referer` y `Origin`
  se conservan), y rechaza `TRACE`, `TRACK` y `CONNECT` dentro del túnel (`405`, sin distinguir
  mayúsculas). `COPY` y `MOVE` (WebDAV, con cabecera `Destination`) solo se reenvían si todas las
  reglas aplicables listan ese método de forma **explícita** (`methods` no vacío que lo contiene);
  si no, `403` (`forbidden`). Incluso entonces `Destination` **no** se valida contra el path de la
  regla. **No** defiende contra overrides de método o ruta transportados en la query o el cuerpo
  (parámetros `_method` de algunos frameworks).

### 6.3 CA acotada

- La CA se crea en el primer arranque con **name constraints** (`permitted dNSName`) limitadas
  a los dominios derivados de las reglas (§7.5); ya no se registran a mano. Un dominio permitido
  cubre sus subdominios.
- Sin dominios permitidos la CA se restringe al TLD reservado `invalid`, de modo que nunca queda
  sin restricciones. El alta de dominios rechaza TLDs y dominios de una sola etiqueta (salvo `localhost`).
  También excluye todas las direcciones IP (`0.0.0.0/0` y `::/0`), porque las restricciones DNS no
  limitan los SAN de tipo IP. El alta valida el nombre con las reglas DNS de webpki y comprueba
  con una hoja de prueba que el nuevo certificado sigue siendo válido para todos los dominios.
  No se consulta la Public Suffix List: el operador es responsable de no crear reglas sobre sufijos
  públicos como `github.io`.
- Añadir un dominio (al crear una regla con un host nuevo) o retirarlo (al borrar la última regla que lo usa) reemite el certificado de la CA **con la misma clave**
  y requiere que los agentes recarguen el certificado público. La UI y la CLI avisan.
- El certificado público se descarga con `sg ca export` o desde la web; la clave privada
  no sale nunca.
- Certificados de hoja de corta duración (24 h) y cacheados en memoria.
- Distribución a los agentes por variable de entorno (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`,
  `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`), no por el almacén del sistema.

### Red y túneles

- Política de red del proxy: el destino se resuelve una sola vez y se conecta a la dirección ya
  validada. Se rechazan (`403`, decisión `target-denied`) las direcciones sin especificar
  (`0.0.0.0`, `::`), `0.0.0.0/8` y `240.0.0.0/4`, link-local (169.254.0.0/16 y fe80::/10, que
  incluye los metadatos de la nube), los metadatos fuera de link-local (`100.100.100.200` de
  Alibaba y `fd00:ec2::254` de AWS IPv6), multicast, broadcast y las direcciones de `denied`.
  Las direcciones IPv6 que embeben una IPv4 (mapeada, compatible, NAT64 `64:ff9b::/96` y
  `64:ff9b:1::/48`, 6to4 `2002::/16`) se juzgan como esa IPv4; Teredo queda fuera de alcance.
  100.64.0.0/10 (Tailscale), RFC 1918 y ULA se permiten (homelab).
- `denied` cubre las direcciones loopback y sin especificar en los puertos indicados (`0.0.0.0:9090`
  bloquea el 9090 en loopback y en las direcciones sin especificar), **no** las demás direcciones de
  las interfaces del equipo: quien arranca el servicio debe añadirlas, y `NetPolicy::denied_for_binds`
  lo hace (para un bind sin especificar añade cada dirección de interfaz con ese puerto).
- Loopback se rechaza salvo `--allow-loopback-targets` o, **solo en peticiones reenviadas por TLS**
  (dentro de un CONNECT con MITM), el host exacto `localhost` con regla aplicable (nunca sobre
  `denied`; un agente no puede forjar un certificado válido para `localhost`). `localhost` se
  resuelve solo a 127.0.0.1 y ::1 sin consultar el resolvedor del sistema (RFC 6761);
  `foo.localhost` no está cubierto. El puerto no forma parte de la autorización: una regla para un
  host vale para cualquier puerto de ese host, por eso nunca se inyecta sin TLS (6.1, punto 7).
- Límites de túnel: el permiso del tope de conexiones vive lo que vive el túnel; el handshake TLS
  del MITM, la inactividad (`tunnel_idle_timeout`, 10 min) y la vida máxima (`tunnel_max_lifetime`,
  8 h) están acotados, y hay un tope global de conexiones salientes (`max_upstream_connections`, 256).
  La vida máxima también acota las conexiones de cliente HTTP en claro (keep-alive); en los túneles
  *passthrough* la inactividad se mide en ambos sentidos y una escritura bloqueada durante ese tiempo
  corta el túnel aunque el otro sentido siga moviéndose.
- Límites por identidad (`jti`): `max_tunnels_per_identity` (64) y `max_upstream_per_identity` (64,
  de que se reenvía hasta que termina el cuerpo de la respuesta); el exceso recibe `429` con
  `Retry-After: 1` y decisión `identity-limit`, de modo que un token no agota los recursos de otros.
  Un cuerpo en streaming (respuesta al agente o petición al origen) sin progreso durante
  `body_idle_timeout` (60 s) se aborta y libera su conexión saliente y sus contadores.
  En túneles *passthrough* no hay verificación por petición: la revocación de un token solo surte
  efecto cuando el túnel termina, así que queda acotada por la inactividad y la vida máxima.

### 6.4 Hosts sin regla

Por rol: `passthrough` (túnel TCP opaco, sin MITM ni inyección) o `deny` (`403`). Valor por
defecto propuesto: **`passthrough`**, para que los agentes sigan funcionando con hosts que no
necesitan credenciales. **Decisión a confirmar en la revisión.**

### 6.5 Limitaciones conocidas

- Las APIs que autentican por parámetros de query suelen reflejar la URL (`Link`, `Location`,
  `Content-Location`), así que el agente puede ver ahí el valor inyectado. Preferir la inyección
  por cabecera.
- La política de tiempo de respuesta (`response_header_timeout`, 120 s por defecto, configurable en
  `UpstreamConfig`) también cubre subidas lentas cuando el origen espera el cuerpo completo.
- Si la escritura del audit falla, la petición ya reenviada no se deshace (*fail-open* para lo ya
  enviado); se registra un error en el log.
- Las llamadas SQLite son síncronas y corren en los hilos del runtime async; una mejora futura es
  moverlas a `spawn_blocking`.
- Solo se audita el id de la primera regla coincidente.

- Herramientas con certificate pinning, Java (almacén propio) o binarios Go que ignoran las
  variables de entorno no funcionarán con el MITM.
- Si el destino refleja el secreto en su respuesta, el agente lo vería. Fuera de alcance.
- Websockets / `Upgrade` **no están soportados** a través del MITM: las cabeceras del handshake se
  eliminan, así que las conexiones a hosts con regla que dependan de un upgrade fallan.
- Los cuerpos de respuesta truncados se registran en el audit solo con el estado de la cabecera.
- Inyección sobre HTTP en claro: **nunca** se realiza. Una petición `http://` a un host con reglas se
  rechaza con `403` (`plaintext-refused`) sin excepciones. Limitación: los servicios locales sin TLS
  no pueden recibir credenciales inyectadas; hay que usar TLS o poner delante un terminador TLS
  (el host `localhost` con regla sí se inyecta por TLS, 6.3 «Red y túneles»).

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

- Validación estricta de `Host` contra DNS rebinding. Valores aceptados: `localhost:<puerto>`,
  `127.0.0.1:<puerto>` y `[::1]:<puerto>`, más los de `--admin-allowed-host` y
  `--admin-public-url`; siempre con el puerto.
- Al arrancar (o con `sg login-url`, que usa solo el socket Unix) se imprime una URL de un solo
  uso `http://localhost:<puerto>/#t=<token>`. El token va en el **fragmento**, que el navegador
  nunca envía al servidor ni en `Referer`. La página lo lee, lo borra con `history.replaceState`
  y lo canjea con `POST /login` (JSON `{"token": ...}`, con guarda de `Host`, comprobación de
  `Origin` y respuesta `no-store`), que devuelve `{"session": "<64 hex>"}`. El token caduca a
  los 10 minutos, es de un solo uso y hay como máximo 8 pendientes.
- **No se usa cookie.** Los navegadores envían las cookies host-only a *todos* los puertos de
  `localhost` (RFC 6265), de modo que otro proceso local que sirva `http://localhost:3000` y que
  el operador visite recibiría la sesión y podría llamar a la API. La sesión vive en
  `sessionStorage` (aislado por origen, puerto incluido) y se envía como
  `Authorization: Bearer <sesión>` en cada llamada a `/api`; las cookies se ignoran por completo.
  Sesiones de 256 bits, máximo 16, caducidad de 8 h; el servidor guarda solo hashes SHA-256 de
  tokens y sesiones.
- No hay cabecera anti-CSRF: la credencial no es ambiental, y una página de otro origen no puede
  añadir `Authorization` sin un preflight CORS, que el servidor no responde (sin cabeceras CORS).
  Se mantienen: solo `application/json` en escrituras (`415`), `Origin` presente debe ser
  `http://<host permitido>`, límite de cuerpo de 64 KiB y `401` antes que `415`/`400`.
- El servidor limita las conexiones: timeout de lectura de cabeceras (10 s), vida máxima por
  conexión (1 h) y 256 conexiones simultáneas. El cliente de la CLI y `bind_unix` exigen que el
  socket y su directorio padre pertenezcan al usuario actual y que el directorio sea `0700`.
- `Content-Security-Policy` restrictiva; sin recursos de terceros.

### 7.3 CLI

```
sg serve [--key-file|--passphrase] [--proxy-bind] [--admin-bind] [--admin-public-url] [--data-dir] [--socket] [--upstream-ca <pem>]
sg keygen   [--out <fichero>]
sg secret   add|rotate|rm|ls     (add exige la primera regla: --role --host --header|--query
                                  [--path --methods --template])
sg role     add|rm|ls            (--unmatched passthrough|deny)
sg rule     add|rm|ls            (--role --host --path --methods --header|--query --template --secret)
sg token    create|revoke|ls     (--machine --role --ttl)
sg ca       export|status
sg audit       [--role --host --since]
```

`sg secret add` lee el valor de stdin o de un prompt sin eco, nunca de argumentos de línea
de comandos (evita que aparezca en el historial y en `ps`).

### 7.4 Web

Frontend estático sin build de Node, embebido en el binario. Pantallas: secretos (solo metadatos),
roles y reglas, tokens (el valor se muestra una vez), CA (descargar certificado, dominios
derivados de las reglas, solo lectura), audit log. El formulario de alta de secreto incluye el
bloque de su primera regla (obligatorio) y «Add another rule».

### 7.5 Alta de secretos con reglas y CA derivada

**Invariante:** todo secreto tiene al menos una regla. Un secreto sin regla no se inyectaría nunca.

- **Crear.** `POST /secrets` recibe `{name, value, rules: [...]}` con al menos una regla (`role`,
  `host`, `path`, `methods`, `header`|`query`, `template`). Se valida todo antes de escribir y
  secreto y reglas se guardan en una sola transacción. Sin reglas, o con una regla inválida
  (incluido un host que la CA rechaza), responde `400` y no se crea nada. La CLI y la web usan
  la misma operación.
- **Reglas adicionales.** `POST /rules` sigue existiendo. Borrar la última regla de un secreto
  responde `409` (hay que borrar el secreto). Borrar un secreto borra sus reglas en la misma
  transacción.
  Una regla idéntica a otra existente (mismo rol, host, path, métodos —como conjunto—, inyección,
  plantilla y secreto) se rechaza con `409` y el id de la existente; sirve igual en el alta de un
  secreto (dos reglas iguales en la misma petición no crean nada).
- **Borrar un rol** borra sus reglas (cascada del esquema). Si eso dejara algún secreto sin reglas, responde `409`
  con los nombres de los secretos afectados y no borra nada; en caso contrario la CA se resincroniza.
- **Secretos anteriores a la enmienda** sin reglas siguen siendo válidos (nunca se inyectan); el
  listado informa del número de reglas y la web los marca con un aviso.
- **Rol por defecto.** Si solo existe un rol, el formulario y la CLI lo preseleccionan. Si no
  existe ninguno, se crea antes `default` (`unmatched = passthrough`) como paso aparte; si el alta
  del secreto falla, ese rol queda creado y es inofensivo.
- **CA derivada.** Los dominios permitidos son exactamente los hosts de las reglas existentes,
  normalizados; `*.x` se traduce a `x`, que por RFC 5280 cubre `x` y sus subdominios (algo más
  ancho que la regla; se documenta). Se recalculan tras cada cambio de reglas o secretos y la CA
  solo se reemite si el conjunto cambia. Sin reglas vuelve al placeholder `invalid`. La
  validación del §6.3 se ejecuta antes de confirmar, y regla y CA cambian juntas o no cambian.
  Al arrancar se sincroniza una vez con las reglas existentes.
- **Aviso a los agentes.** La respuesta incluye `ca_changed`. Si se añadió un dominio, los agentes
  deben recargar el certificado; la CLI y la web lo indican junto con la ruta o el comando para
  obtener el PEM vigente. Tras retirar un dominio no es urgente.
- **Se eliminan** `sg ca allow-domain` y su endpoint (cambio incompatible aceptado: la rama no se
  ha publicado). La librería conserva `CaService::allow_domain` y añade `prepare_domains`/`persist`/`install` y `domain_guard` (se adquiere antes de la transacción y se mantiene hasta después de `install`).
- **Pruebas:** API (atomicidad, `400`, `409`, cascada), sincronización de la CA (añadir, retirar,
  comodín, rechazo sin efectos, reinicio), CLI y web.


## 8. Errores y observabilidad

- Códigos del proxy: `407` sin token válido, `403` sin regla o método no permitido, `502` si falla
  el destino. Los mensajes no incluyen valores ni detalles de reglas.
- `tracing` estructurado; los valores secretos y los tokens nunca se registran.
- El audit log se escribe de forma síncrona cuando se ha recibido la cabecera de respuesta del
  destino y antes de devolverla al agente (si el proxy rechaza la petición, antes de devolver el
  rechazo). Los fallos de autenticación (`407`) no se auditan, salvo el de un token con firma y emisor
  válidos pero revocado o caducado: decisión `token-invalid`, estado `407`, con la identidad del
  token (`jti`, máquina, rol) y como mucho una fila por `jti` cada 60 s (mapa en memoria acotado
  a 4096 entradas; si está lleno de entradas vigentes, un `jti` nuevo no se audita). Un cliente
  anónimo (sin token, mal formado, firma o emisor incorrectos, `jti` desconocido) no puede por
  tanto llenar el audit. La respuesta es idéntica a cualquier otro `407` (no hay oráculo entre
  «revocado» e «inválido»). Los destinos CONNECT o de
  forma absoluta mal formados (`400`) de un agente autenticado se auditan como `bad-request` con
  su identidad. Si la escritura del audit falla, se registra
  en el log y no bloquea una petición ya reenviada. Los cuerpos de respuesta truncados se
  registran con el estado de la cabecera que se envió.

## 9. Pruebas

- **Unitarias:** cifrado/descifrado y KEK errónea, derivación Argon2, matching de reglas
  (especificidad, wildcards, métodos), emisión/verificación/revocación de tokens, plantillas.
- **Integración:** proxy contra un servidor de prueba TLS local; comprobar inyección en header y
  query, sobrescritura de la cabecera enviada por el agente, `407`/`403`, streaming de cuerpos
  grandes, hosts sin regla en ambos modos.
- **CA:** un cliente `rustls` rechaza una hoja de un dominio fuera de las name constraints.
- **Seguridad:** ninguna respuesta de la API contiene el valor; un volcado de la DB no contiene
  el valor en claro; validación de `Host`/`Origin` en la web; las cookies se ignoran y la API exige `Authorization: Bearer`.
- **E2E:** script con `curl` a través del proxy, con y sin CA, y rol `reviewer` frente a `developer`.

## 10. Fases

1. **Esta spec:** núcleo cifrado, CA acotada, proxy con inyección en header/query, tokens por
   (máquina, rol), reglas, audit, CLI y web local.
2. Sidecar / launcher `sg run` (el agente no ve el token).
   2b. **Autenticación por proceso.** El proxy escucha también en un socket Unix y deduce el rol
   del cliente con `SO_PEERCRED` (uid/pid) mapeado a roles, de modo que no existe token que robar.
   Exige usuarios, contenedores o namespaces distintos por rol y no sirve entre agentes del mismo
   usuario; convive con los tokens y se diseñaría junto a `sg run`. Pendiente de brainstorm y spec
   propia. Registrada el 2026-10-19 a petición del operador.
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
