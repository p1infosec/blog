# Testando DPoP (Demonstrating Proof-Of-Possession)

Recentemente, um de nossos clientes nos pediu para verificar a possibilidade de contornar as proteções instauradas pelo DPoP em sua aplicação web. DPoP, Demonstrating Proof-of-Possession, é uma extensão de segurança do Outh 2.0 definida no RFC 9449.

Este é um mecanismo eficaz para mitigar ataques de replay envolvendo JSON Web Tokens (JWT), pois cada token é assinado para um uso específico (endpoint) e uma quantidade limitada, restringindo sua reutilização arbitrária. Para a assinatura, são necessárias as chaves pública e privada em formato JSon Web Key (JWK).

Em nosso cenário, o cliente queria evitar que o token fosse consumido por terceiros (com acesso autorizado na aplicação) para a extração, de forma automatizada e em tempo real, de dados, o que estava gerando uma série de problemas de confidencialidade e de disponibilidade da aplicação.

A estrutura e cabeçalho do DPoP têm a seguinte característica:

```
CLIENTE
  |
  |  HTTP REQUEST
  |------------------------------------------------------------>
  |
  |  Authorization: DPoP <access_token>
  |
  |  DPoP: <JWT assinado com chave privada>
  |        {
  |          htm : HTTP Method (GET / POST)
  |          htu : URL da requisição
  |          iat : timestamp
  |          jti : identificador único (anti-replay)
  |        }
  v
SERVIDOR
  |
  |  1. Valida assinatura com chave pública
  |
  |  2. Confirma:
  |       - htm == método recebido
  |       - htu == URL recebida
  |
  |  3. Verifica se jti já foi usado
  |       -> se usado: REPLAY
  |       -> se novo : processa requisição
```

Dois pontos bem importantes na assinatura são o `htu` e o `jti`. O `htu` vai limitar o uso do token somente na URL definida, ou seja, se estou acessando `/admin/`, esse token só poderá ser usado no mesmo endpoint. O `jti` é então verificado pelo servidor para entender se já foi usado e quantas vezes -- pode-se configurar este recurso para permitir o uso múltiplas vezes.

Alguns problemas no DPoP são similares aos de quaisquer tokens JWT. A possibilidade de remoção da assinatura (`"alg":"none"`) e modificação de funções, como no caso `htu` ou mesmo no método `htm`. E, claro, verificar se os controles estavam estabelecidos de acordo e o proposto estava sendo feito, e no caso realmente estavam.

### Mas como o cliente faz uma assinatura prévia a cada requisição?

De fato, a assinatura ocorre no cliente, ou seja, no browser durante a navegação na aplicação. As chaves são disponibilizadas de alguma forma ao navegador que usa esses dados (baseado na RFC) para a assinatura de requisições de forma transparente.

A chave pública é quase sempre disponibilizada em recursos de armazenamento do navegador: localStorage, sessionStorage, Indexed DB, etc.

A chave JWK tem o seguinte formato:
```
{
  "kty": "EC",
  "crv": "P-256",
  "x": "f83OJ3D2xF4v1xWw2XHDLZ6kRz7sH9x8yWm4c5Q6r7s",
  "y": "x_FEzRu9xR3W4Jc7bLkP9sT6uV1wX2yZ3aB4cD5eF6g",
  "use": "sig",
  "alg": "ES256",
  "key_ops": ["verify"],
  "ext": true
}
```
E a chave estará armazenada neste formato:

```
{
  "id": "dpop-key",
  "publicKey": {BASE64(KEY)},
  "createdAt": 1739473821
}
```

Já a chave privada, pode ou não ser facilmente encontrada, se encontrada -- da mesma forma que a pública -- mas geralmente essa não é exportável, definida assim como no exemplo abaixo:
```
const keyPair = await crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  false, // <-- extractable = false
  ["sign", "verify"]
);
```
No caso, temos a chave pública em mãos e a chave privada não exportável para gerarmos a assinatura válida; ou seja, temos que fazer isso de forma dinâmica.
As aplicações modernas (React, Vue, Next, etc.) são empacotadas com Webpack, e o código original é transformado em módulos numerados, nomes ofuscados, funções encapsuladas e variáveis inacessíveis no `window`, em outras palavras, não é possível acessar diretamente funções internas como `generateKeyPair()`.
Então definimos a seguinte estratégia:

1. Descoberta do webpackChunk*: Varremos `window` até achar uma chave cujo nome começa com webpackChunk e cujo valor é um array.
2. Injetamos um chunk para capturar `__webpack_require__: Faz window[chunkName].push([...])` com um `callback (req) => { __webpack_require__ = req; }`. Esse callback recebe a função interna do Webpack `(__webpack_require__)`, que permite acessar módulos e cache.
3. Varremos e forçamos `require()` de módulos candidatos: Acessa `__webpack_require__.m` (mapa de fábricas de módulos) e procura módulos cujo `toString()` contém strings indicativas, como `"dpop+jwt"` ou `"createProof"`. Para esses módulos, executa `__webpack_require__(id)` para garantir que entrem no cache.
4. Procuramos no cache um módulo com a “assinatura” esperada: Percorre `__webpack_require__.c` (cache de módulos carregados). Se encontrarmos um objeto com duas funções: `generateKeyPair()` e `createProof()`, assumimos que achamos o helper de DPoP.

Neste ponto, se tivermos sucesso, já temos o objeto exportado do módulo Webpack e nele vamos ter o objeto JavaScript `keyPair` que vai conter as instâncias `privateKey` e `publicKey`. Podemos então assinar uma requisição usando um script como este:

```
async function buildDpopJwt(privateKey, publicKey, htu, htm, opts) {
  opts = opts || {};
  const now = Math.floor(Date.now() / 1000);
  const iat = opts.iat != null ? opts.iat : now;
  const jti = opts.jti || crypto.randomUUID();

  const pubJwk = await crypto.subtle.exportKey("jwk", publicKey);
  delete pubJwk.d;          
  pubJwk.alg = "ES256";
  pubJwk.key_ops = ["verify"];
  pubJwk.ext = true;

  const header = {
    alg: "ES256",
    typ: "dpop+jwt",
    jwk: pubJwk,
  };

  const payload = {
    htu: htu,
    htm: htm.toUpperCase(),
    iat: iat,
    jti: jti,
  };

  const headerJson = JSON.stringify(header);
  const payloadJson = JSON.stringify(payload);

  const headerB64 = base64UrlEncodeString(headerJson);
  const payloadB64 = base64UrlEncodeString(payloadJson);
  const signingInput = headerB64 + "." + payloadB64;

  const enc = new TextEncoder();
  const data = enc.encode(signingInput);

  const sigBuf = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    data
  );

  const sigB64 = base64UrlEncodeBytes(new Uint8Array(sigBuf));

  const dpopJwt = signingInput + "." + sigB64;

  return {
    header,
    payload,
    dpopJwt,
  };
}
```
Ao final, conseguimos assinar o DPoP para qualquer requisição por meio do modo console do navegador. 

A praticabilidade do ataque é questionável devido à necessidade de acesso a recursos da aplicação ou através de uma vulnerabilidade como um cross-site scripting persistente. Porém, a prova de conceito é mais para entendermos as características do mecanismo. 

Este é um exemplo em que durante os testes de segurança ofensiva, nem sempre a meta é o comprometimento, mas podemos também validar sistemas de segurança e indicar a melhor solução possível.

Para dúvidas ou detalhes sobre nossos testes, comercial@p1infosec.com.

**Referências:**
* https://medium.com/@yveskerbs89/sender-constrained-dpop-jar-par-oidc-flow-browser-to-rp-full-technical-design-b48431e1e908
* https://auth0.com/blog/protect-your-access-tokens-with-dpop/
