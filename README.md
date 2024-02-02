# Weekly API Server (WAS)

### 目標
- 取代 apigateway 成為 mm-next 與 Israfel（會員系統）和 Content GQL 3.0（CMS GQL）的溝通介面。
- 使用 Firebase Admin SDK 驗證 Firebase ID Token（JWT），將合格的 firebase uid 送往 Israfel，確認使用者的會員資格，WAS 根據會員資格和權限產生使用者專有的 Access Token（JWT），並將其返回給使用者。
- 驗證使用者提供的 Access Token，如果 Token 通過驗證，WAS 會將使用者發送的 requests proxy 到 Israfel 或是 Content GQL 3.0 servers 上。

### 系統架構圖
![mirror-weekly-system-design (2)](https://user-images.githubusercontent.com/3000343/211236890-e6e3eb33-5c20-4a43-892d-b7be12522402.jpg)

### 實作細節
WAS 會起一個 express server，提供 authentication, authorization 等身份認證功能，並且根據使用者的需求，將 request proxy 到 Israfel, Lilith/mirrormedia 等 internal API servers 上。
註：internal API servers 僅在內部網域中，外部的 requests 一定得經過 WAS API server 才能到達。

WAS 會提供以下 endpoints：
- `/access-token` (POST method): 此 endpoint 會根據使用者提供的 ID token (firebase token) 來核發相對應的 access token。Access token 的 JWT payload 中的 `scope` property 會標示使用者的權限（相關討論可以見 https://github.com/mirror-media/Lilith/pull/176）。
- `/member/graphql` (POST method): 此 endpoint 會驗證 `Authorization` header，如果 request 有帶的話，確認 access token 是合格的，且將 `scope` property 帶在 `X-Access-Token-Scope` custom header 後，proxy request 到 Israfel gql server。
- `/content/graphql` (POST method): 此 endpoint 會驗證 `Authorization` header，如果 request 有帶的話，確認 access token 是合格的，且將 `scope` property 帶在 `X-Access-Token-Scope` custom header 後，proxy request 到 Lilith/mirrormedia gql server。

以上 endpoints 也都有提供 OPTIONS method，以方便 requests 通過 browser CORS 限制。


### Installation
```
$ yarn install
```

### Development
```
$ yarn dev
// or
$ make dev
```

### Build Transpiled Codes
```
$ yarn build
// or
$ make build
```

### Start Server on Production
```
// build first
$ make build

// start server
$ make start
// or
$ yarn start
```

### 環境變數設定
請見檔案 [`/src/environment-variables.js`](/src/environment-variables.js)
