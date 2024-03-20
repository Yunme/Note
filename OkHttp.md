# OkHttp 源码


### 特性：
- HTTP/2 支持对同一主机的请求共享TCP连接
- 连接池机制可减少请求延迟（如果 HTTP/2 不可用）
- 自带透明的 GZIP 减少下载内容大小
- 自带响应缓存，可避免重复请求
- 重试机制，请求可在常见连接问题中恢复
- 在连接失败时，会自动尝试连接备用 IP
- 支持现代 TLS
- API 结构清晰易懂，使用 Builder 责任链等设计模式
- 支持同步阻塞调用和异步回调

#### GET 请求示例
```java
OkHttpClient client = new OkHttpClient();
String run(String url) throws IOException {
	Request request = new Request.Builder()
    	.url(url)
		.build();
	try (Response response = client.newCall(request).execute()) {
		return response.body().string();
	}
}
```

#### POST请求示例
```java
public static final MediaType JSON = MediaType.get("application/json");
OkHttpClient client = new OkHttpClient();
String post(String url, String json) throws IOException {
  RequestBody body = RequestBody.create(json, JSON);
  Request request = new Request.Builder()
      .url(url)
      .post(body)
      .build();
  try (Response response = client.newCall(request).execute()) {
    return response.body().string();
  }
}
```
请求执行的方法都是从 `client.newCall(request).execute()` 开始，源码探索就从这里开始。

### OkHttpClient 
最好是单例，可以复用请求。每一个 `OkHttpClient` 实例都持有自己的连接池和线程池。复用连接以减少延迟和节省内存。

OkHttpClient 由 Builder 模式创建，看一下它有哪些参数。
1. dispatcher  Call 的请求执行的调度器
2. connectionPool  管理 HTTP 连接的复用来决定哪些连接应该保持复用，共享同一地址的请求应共享一个连接。
3. interceptors  一个列表可包含若干个拦截器，可以监听一个请求调用的全流程，从建立连接之前到拿到响应之后。
4. networkInterceptors 一个列表可包含若干个网络拦截器，仅仅从 实际HTTP 请求的发起和响应。
5. eventListenerFactory 一个事件监听器工厂，整个网络请求的监听器分为若干个阶段
6. retryOnConnectionFailure 是否当 IP 不可达、连接池过时、代理服务器不可达时让 OkHttp 来自动重试，默认为 `true`
7. fastFallback 
8. authenticator 请求的身份验证器
9. followRedirects 是否自动重定向，默认为 `true`
10. followSslRedirects 是否允许请求从 HTTP 到 HTTPS 或 从 HTTPS 到 HTTP 重定向，默认为 `true`
11. cookiesJar 处理来自服务器响应里的 Cookie 和 请求时带给 服务器的 Cookie，默认不处理
12. cache 处理一个用来存储读写缓存响应的响应缓存，默认无
13. dns DNS 服务器，查找域名的 IP 地址，默认使用系统的
14. proxy 代理服务器 比 `proxySelector` 优先级高，默认无代理服务器
15. proxySelector 选择代理服务器的规则。默认使用系统的
16. proxyAuthenticator 代理服务器的身份验证器，默认无
17. socketFactory 创建连接的 socket 工厂，默认使用系统的
18. sslSocketFactory 创建安全的 HTTPS 连接的 socket 工厂，默认使用系统的
19. x509TrustManager 
20. connectionSpecs 一个列表可包含若干个设置 socket 连接的配置，默认包含现代 TLS 和 HTTP
21. protocols 一个列表设置支持的协议，默认包含 HTTP1.1 和 HTTP2
22. hostnameVerifier 一个用来确认服务端响应证书是否跟HTTPS连接请求的主机名匹配，默认使用 OKHTTP 自带的
23. certificatePinner 用来约束哪个证书可以被信任。
24. certificateChainCleaner
25. callTimeoutMillis 完整的一个请求到响应结束的超时时间，从域名解析、连接建立、请求发起、服务器处理、响应到结束，如果请求需要重定向或者重试，也必须要在超时前完成。默认为0代表无超时时间控制
26. connectTomeoutMillis 新的 TCP 连接到目标地址的超时时间，默认10s
27. readTimeoutMillis 从 TCP 连接里 IO 操作里读取的超时时间，默认10s
28. writeTimeoutMillis 写入 IO 操作的超时时间，默认10s
29. pingIntervalMillis WebSocket 下 心跳的间隔时间，默认0，代表不心跳。

可以看到 Client 有很多参数可以设置，在请求和响应流程中慢慢提及。

### Request 
接下来看看 HTTP 请求 `Request` 类，也由 Builder 模式创建，参数如下
1. url 请求的 url，应该是一个合法的 url
2. method HTTP 请求方法，如：'GET', 'POST'
3. headers HTTP 请求头部列表
4. body HTTP 请求body
5. tag 请求标记
6. cacheControl

#### RequestBody

主要是包装一些请求信息，接下来看组装真正的 `Call`
```kotlin
fun newCall(request: Request): Call = RealCall(this, request, forWebSocket = false)
```

### RealCall
`RealCall` 是一个从应用使用到真正 HTTP 请求的桥梁，包含：连接、请求、响应、流等。

#### 同步请求

直接从同步请求 `execute()` 方法看起

```kotlin
fun execute(): Response {
    check(executed.compareAndSet(false, true)) { "Already Executed" }

    timeout.enter()
    callStart()
    try {
      client.dispatcher.executed(this)
      return getResponseWithInterceptorChain()
    } finally {
      client.dispatcher.finished(this)
    }
  }
```
逐行来分析下
```
check(executed.compareAndSet(false, true)) { "Already Executed" } 
```
检查是否执行过，并设置 `executed` 为 `true` ，一个 `RealCall` 只执行一次，否则抛出异常。
``` 
timeout.enter()
```
异步的 `AsyncTimeout` 倒计时开始计时，倒计时时间为 client 中的 `callTimeoutMillis` ，当超时后，调用 `cancel()` 
```kotlin
private val timeout = object : AsyncTimeout() {
      override fun timedOut() {
        this@RealCall.cancel()
      }
    }.apply {
      timeout(client.callTimeoutMillis.toLong(), MILLISECONDS)
    }
```
接着调用事件监听器，代表 call 开始启动
``` kotlin
 private fun callStart() {
    this.callStackTrace = Platform.get().getStackTraceForCloseable("response.body().close()")
    eventListener.callStart(this)
  }
```
接着调用 `dispatcher.executed(this)` 把当前 call 加入到 `runningSyncCalls` 中

#### 异步请求
``` kotlin
    client.dispatcher.enqueue(AsyncCall(responseCallback))
```
看下 `AsyncCall` 这个类，其实就是个 `Runnable`，在其 `run()` 方法中调用了 `getResponseWithInterceptorChain()` 并进行了回调。
``` kotlin
override fun run() {
      threadName("OkHttp ${redactedUrl()}") {
        var signalledCallback = false
        timeout.enter()
        try {
          val response = getResponseWithInterceptorChain()
          signalledCallback = true
          responseCallback.onResponse(this@RealCall, response)
        } catch (e: IOException) {
          if (signalledCallback) {
            // Do not signal the callback twice!
            Platform.get().log("Callback failure for ${toLoggableString()}", Platform.INFO, e)
          } else {
            responseCallback.onFailure(this@RealCall, e)
          }
        } catch (t: Throwable) {
          cancel()
          if (!signalledCallback) {
            val canceledException = IOException("canceled due to $t")
            canceledException.addSuppressed(t)
            responseCallback.onFailure(this@RealCall, canceledException)
          }
          throw t
        } finally {
          client.dispatcher.finished(this)
        }
      }
    }
```
接着看 `enqueue()` 里的 `promoteAndExecute()`
将符合条件的 call 从 ready 列表移到 running 列表中，并加到线程池里执行。
``` kotlin
fun promoteAndExecute(): Boolean {
    this.assertThreadDoesntHoldLock()

    val executableCalls = mutableListOf<AsyncCall>()
    val isRunning: Boolean
    synchronized(this) {
      val i = readyAsyncCalls.iterator()
      while (i.hasNext()) {
        val asyncCall = i.next()

		// 大于最大请求数
        if (runningAsyncCalls.size >= this.maxRequests) break
        // 大于单个 host 最大请求数
        if (asyncCall.callsPerHost.get() >= this.maxRequestsPerHost) continue

        i.remove()
        asyncCall.callsPerHost.incrementAndGet()
        executableCalls.add(asyncCall)
        runningAsyncCalls.add(asyncCall)
      }
      isRunning = runningCallsCount() > 0
    }

    for (i in 0 until executableCalls.size) {
      val asyncCall = executableCalls[i]
      // 调用线程池执行。
      asyncCall.executeOn(executorService)
    }

    return isRunning
  }
```
最后调用 `asyncCall.executeOn()` 执行
``` kotlin
fun executeOn(executorService: ExecutorService) {
      client.dispatcher.assertThreadDoesntHoldLock()

      var success = false
      try {
        executorService.execute(this)
        success = true
      } catch (e: RejectedExecutionException) {
        val ioException = InterruptedIOException("executor rejected")
        ioException.initCause(e)
        noMoreExchanges(ioException)
        responseCallback.onFailure(this@RealCall, ioException)
      } finally {
        if (!success) {
          client.dispatcher.finished(this) // This call is no longer running!
        }
      }
    }
```

接下来看核心方法 `getResponseWithInterceptorChain()`

``` kotlin
	// Build a full stack of interceptors.
    val interceptors = mutableListOf<Interceptor>()
    interceptors += client.interceptors
    interceptors += RetryAndFollowUpInterceptor(client)
    interceptors += BridgeInterceptor(client.cookieJar)
    interceptors += CacheInterceptor(client.cache)
    interceptors += ConnectInterceptor
    if (!forWebSocket) {
      interceptors += client.networkInterceptors
    }
    interceptors += CallServerInterceptor(forWebSocket)
```
可以看到是一系列的拦截器，最前面的是用户手动添加的拦截器，而后依次是 
- `RetryAndFollowUpInterceptor` 用来重试和重定向的拦截器、
- `BridgeInterceptor` 桥接应用代码到真实 HTTP 请求的，在访问网络后，再构建网络响应到用户影响的拦截器
- `CacheInterceptor` 处理缓存的拦截器，把响应写入缓存，并把符合条件的缓存直接返回
- `ConnectInterceptor` 处理连接的拦截器
- `networkInterceptors` 用来处理真正 HTTP 请求的拦截器
- `CallServerInterceptor` 最后一个拦截器，向服务器进行真实的网络请求

接下来真正的链条开始组装，开始处理：
``` kotlin
val chain = RealInterceptorChain(
        call = this,
        interceptors = interceptors,
        index = 0,
        exchange = null,
        request = originalRequest,
        connectTimeoutMillis = client.connectTimeoutMillis,
        readTimeoutMillis = client.readTimeoutMillis,
        writeTimeoutMillis = client.writeTimeoutMillis,
      )
```
链条开始启动：
``` kotlin
val response = chain.proceed(originalRequest)
```
首先看下是如何启动的：
``` kotlin
fun proceed(request: Request): Response {
	// 检查拦截器列表索引是否越界
    check(index < interceptors.size)

    calls++

    if (exchange != null) {
      check(exchange.finder.routePlanner.sameHostAndPort(request.url)) {
        "network interceptor ${interceptors[index - 1]} must retain the same host and port"
      }
      check(calls == 1) {
        "network interceptor ${interceptors[index - 1]} must call proceed() exactly once"
      }
    }

    // 链上的下一个拦截器
    val next = copy(index = index + 1, request = request)
    val interceptor = interceptors[index]

    @Suppress("USELESS_ELVIS")
    // 调用拦截器的拦截实现方法，从这里开始启动---
    val response =
      interceptor.intercept(next) ?: throw NullPointerException(
        "interceptor $interceptor returned null",
      )

    if (exchange != null) {
      check(index + 1 >= interceptors.size || next.calls == 1) {
        "network interceptor $interceptor must call proceed() exactly once"
      }
    }

    return response
  }
```
而在每个拦截器里的 intercept 方法里使用 `chain.proceed(request)` 调用链上的下一个拦截器，大致流程如下
接下来根据网络请求流程挨个解析每个内置拦截器

## 请求发起阶段

#### RetryAndFollowUpInterceptor
在网络请求发起初始，这个拦截器需要做的很少，主要是一些参数的记录。毕竟重试和重定向需要一次请求响应后根据网络情况和响应结果来判断是否需要。
``` kotlin
fun intercept(chain: Interceptor.Chain): Response {
    val realChain = chain as RealInterceptorChain
    var request = chain.request
    val call = realChain.call
    var followUpCount = 0
    var priorResponse: Response? = null
    var newRoutePlanner = true
    var recoveredFailures = listOf<IOException>()
    while (true) {
      // 为后面连接做准备
      call.enterNetworkInterceptorExchange(request, newRoutePlanner, chain)

      var response: Response
      var closeActiveExchange = true
      try {
        if (call.isCanceled()) {
          throw IOException("Canceled")
        }

        try {
          response = realChain.proceed(request)
```
看下 `enterNetworkInterceptorExchange` 方法
```kotlin
fun enterNetworkInterceptorExchange(request: Request, newExchangeFinder: Boolean) {
    check(interceptorScopedExchange == null)

    synchronized(this) {
      check(!responseBodyOpen) {
        "cannot make a new request because the previous response is still open: " +
            "please call response.close()"
      }
      check(!requestBodyOpen)
    }

    if (newExchangeFinder) {
      this.exchangeFinder = ExchangeFinder(
          connectionPool,
          createAddress(request.url),
          this,
          eventListener
      )
    }
  }
```

其中 address 是创建一个 `Address` 实例，透传一些 TCP 连接需要的参数。
``` kotlin
fun createAddress(url: HttpUrl): Address {
    var sslSocketFactory: SSLSocketFactory? = null
    var hostnameVerifier: HostnameVerifier? = null
    var certificatePinner: CertificatePinner? = null
    if (url.isHttps) {
      sslSocketFactory = client.sslSocketFactory
      hostnameVerifier = client.hostnameVerifier
      certificatePinner = client.certificatePinner
    }

    return Address(
        uriHost = url.host,
        uriPort = url.port,
        dns = client.dns,
        socketFactory = client.socketFactory,
        sslSocketFactory = sslSocketFactory,
        hostnameVerifier = hostnameVerifier,
        certificatePinner = certificatePinner,
        proxyAuthenticator = client.proxyAuthenticator,
        proxy = client.proxy,
        protocols = client.protocols,
        connectionSpecs = client.connectionSpecs,
        proxySelector = client.proxySelector
    )
}
```
最终生成一个 `ExchangeFinder` 对象。

#### BridgeInterceptor
主要是填充一些 HTTP 请求需要的 header 字段
```kotlin
fun intercept(chain: Interceptor.Chain): Response {
    val userRequest = chain.request()
    val requestBuilder = userRequest.newBuilder()

    val body = userRequest.body
    if (body != null) {
      val contentType = body.contentType()
      if (contentType != null) {
      	// 填充 Content-Type
        requestBuilder.header("Content-Type", contentType.toString())
      }

      val contentLength = body.contentLength()
      if (contentLength != -1L) {
      	// 自动填充 Content-Length
        requestBuilder.header("Content-Length", contentLength.toString())
        // 当 Content-Length 确定时，移除分段传输标记 
        requestBuilder.removeHeader("Transfer-Encoding")
      } else {
      	// contentLength 未知时，则为分块传输
        requestBuilder.header("Transfer-Encoding", "chunked")
        requestBuilder.removeHeader("Content-Length")
      }
    }

    if (userRequest.header("Host") == null) {
      // 填充 Host
      requestBuilder.header("Host", userRequest.url.toHostHeader())
    }

    if (userRequest.header("Connection") == null) {
      // HTTP/1.1 版本的默认连接都是持久连接
      requestBuilder.header("Connection", "Keep-Alive")
    }

    // 自动添加 Gzip 压缩
    var transparentGzip = false
    if (userRequest.header("Accept-Encoding") == null && userRequest.header("Range") == null) {
      transparentGzip = true
      requestBuilder.header("Accept-Encoding", "gzip")
    }

	// 填充 Cookie
    val cookies = cookieJar.loadForRequest(userRequest.url)
    if (cookies.isNotEmpty()) {
      requestBuilder.header("Cookie", cookieHeader(cookies))
    }
	// 填充 user-Agent
    if (userRequest.header("User-Agent") == null) {
      requestBuilder.header("User-Agent", USER_AGENT)
    }

    val networkRequest = requestBuilder.build()
    val networkResponse = chain.proceed(networkRequest)
```

#### CacheInterceptor
根据请求头部信息从本地缓存中查找缓存的响应，如果命中缓存，则组装成 Response 返回，请求链结束；如果无缓存命中，则继续调用下一个拦截器，进行网络请求。
``` kotlin
fun intercept(chain: Interceptor.Chain): Response {
    val call = chain.call()
    // 根据请求 Request 得到一个备选缓存
    val cacheCandidate = cache?.get(chain.request())

    val now = System.currentTimeMillis()

	// 根据当前时间、请求和备选缓存来计算缓存策略。
    val strategy = CacheStrategy.Factory(now, chain.request(), cacheCandidate).compute()
    val networkRequest = strategy.networkRequest
    val cacheResponse = strategy.cacheResponse

    cache?.trackResponse(strategy)
    val listener = (call as? RealCall)?.eventListener ?: EventListener.NONE
	// 如果备选缓存不为空，但响应缓存为空，说明备选缓存不可用。
    if (cacheCandidate != null && cacheResponse == null) {
      // The cache candidate wasn't applicable. Close it.
      cacheCandidate.body?.closeQuietly()
    }

    // networkRequest 为空说明缓存策略计算出来不需要进行网络请求，但缓存的响应内容又为空，异常状态。
    // 如果网络请求和缓存响应都为空时，说明缓存不可用，返回 504 错误
    if (networkRequest == null && cacheResponse == null) {
      return Response.Builder()
          .request(chain.request())
          .protocol(Protocol.HTTP_1_1)
          .code(HTTP_GATEWAY_TIMEOUT)
          .message("Unsatisfiable Request (only-if-cached)")
          .body(EMPTY_RESPONSE)
          .sentRequestAtMillis(-1L)
          .receivedResponseAtMillis(System.currentTimeMillis())
          .build().also {
            listener.satisfactionFailure(call, it)
          }
    }

    // 网络请求为空，缓存响应不为空，不需要进行网络请求，返回缓存的响应内容
    if (networkRequest == null) {
      return cacheResponse!!.newBuilder()
          .cacheResponse(stripBody(cacheResponse))
          .build().also {
            listener.cacheHit(call, it)
          }
    }
	
	// 缓存响应不为空，网络请求不为空，代表缓存只有部分命中或未命中缓存。
    if (cacheResponse != null) {
      listener.cacheConditionalHit(call, cacheResponse)
    } else if (cache != null) {
      listener.cacheMiss(call)
    }

	// 未命中缓存 进行网络请求
    var networkResponse: Response? = null
    try {
      networkResponse = chain.proceed(networkRequest)
    } finally {
     // 备选缓存关闭 
      if (networkResponse == null && cacheCandidate != null) {
        cacheCandidate.body?.closeQuietly()
      }
    }

    // If we have a cache response too, then we're doing a conditional get.
    // 缓存响应和网络响应都有，更新缓存
    if (cacheResponse != null) {
      // 304 服务器未修改，合并 header，服务器不返回 body，直接用缓存的 body
      if (networkResponse?.code == HTTP_NOT_MODIFIED) {
        val response = cacheResponse.newBuilder()
            .headers(combine(cacheResponse.headers, networkResponse.headers))
            .sentRequestAtMillis(networkResponse.sentRequestAtMillis)
            .receivedResponseAtMillis(networkResponse.receivedResponseAtMillis)
            .cacheResponse(stripBody(cacheResponse))
            .networkResponse(stripBody(networkResponse))
            .build()

        networkResponse.body!!.close()

        // 更新缓存
        cache!!.trackConditionalCacheHit()
        cache.update(cacheResponse, response)
        return response.also {
          listener.cacheHit(call, it)
        }
      } else {
      // 不是 304，缓存 body 不需要使用
        cacheResponse.body?.closeQuietly()
      }
    }
	
	// 更新缓存，构建响应返回。
    val response = networkResponse!!.newBuilder()
        .cacheResponse(stripBody(cacheResponse))
        .networkResponse(stripBody(networkResponse))
        .build()

    if (cache != null) {
      // 可以缓存的话 将请求和响应放入缓存
      if (response.promisesBody() && CacheStrategy.isCacheable(response, networkRequest)) {
        // Offer this request to the cache.
        val cacheRequest = cache.put(response)
        return cacheWritingResponse(cacheRequest, response).also {
          if (cacheResponse != null) {
            // This will log a conditional cache miss only.
            listener.cacheMiss(call)
          }
        }
      }

      if (HttpMethod.invalidatesCache(networkRequest.method)) {
        try {
          cache.remove(networkRequest)
        } catch (_: IOException) {
          // The cache cannot be written.
        }
      }
    }

    return response
  }
```

#### ConnectInterceptor

打开一个连接到目标服务器的链接，交给下个拦截器，虽然这个拦截器代码看起来较少，因为都封装到其他类了。

``` kotlin
fun intercept(chain: Interceptor.Chain): Response {
    val realChain = chain as RealInterceptorChain
    val exchange = realChain.call.initExchange(realChain)
    val connectedChain = realChain.copy(exchange = exchange)
    return connectedChain.proceed(realChain.request)
  }
```
先看 `RealCall.initExchange()` 方法，此方法构造一个 `Exchange` 实例，此类主要是传输单个 HTTP 请求和响应。
``` kotlin
fun initExchange(chain: RealInterceptorChain): Exchange {
    synchronized(this) {
      check(expectMoreExchanges) { "released" }
      check(!responseBodyOpen)
      check(!requestBodyOpen)
    }

    val exchangeFinder = this.exchangeFinder!!
    val codec = exchangeFinder.find(client, chain)
    val result = Exchange(this, eventListener, exchangeFinder, codec)
    this.interceptorScopedExchange = result
    this.exchange = result
    synchronized(this) {
      this.requestBodyOpen = true
      this.responseBodyOpen = true
    }

    if (canceled) throw IOException("Canceled")
    return result
  }
```
看看 `exchangeFinder.find()` 方法，找到一个已有的连接并转换为交换请求和响应的编码器。
``` kotlin
 fun find(
    client: OkHttpClient,
    chain: RealInterceptorChain
  ): ExchangeCodec {
    try {
      val resultConnection = findHealthyConnection(
          connectTimeout = chain.connectTimeoutMillis,
          readTimeout = chain.readTimeoutMillis,
          writeTimeout = chain.writeTimeoutMillis,
          pingIntervalMillis = client.pingIntervalMillis,
          connectionRetryEnabled = client.retryOnConnectionFailure,
          doExtensiveHealthChecks = chain.request.method != "GET"
      )
      return resultConnection.newCodec(client, chain)
    } catch (e: RouteException) {
      trackFailure(e.lastConnectException)
      throw e
    } catch (e: IOException) {
      trackFailure(e)
      throw RouteException(e)
    }
  }
```
看看 `findHealthyConnection()` 方法，找到一个健康可用的连接，如果不可用，那就重复查找，知道找到。
``` kotlin
private fun findHealthyConnection(
    connectTimeout: Int,
    readTimeout: Int,
    writeTimeout: Int,
    pingIntervalMillis: Int,
    connectionRetryEnabled: Boolean,
    doExtensiveHealthChecks: Boolean
  ): RealConnection {
    while (true) {
      val candidate = findConnection(
          connectTimeout = connectTimeout,
          readTimeout = readTimeout,
          writeTimeout = writeTimeout,
          pingIntervalMillis = pingIntervalMillis,
          connectionRetryEnabled = connectionRetryEnabled
      )

      // 确认连接是可用的
      if (candidate.isHealthy(doExtensiveHealthChecks)) {
        return candidate
      }

      // 如果不可用，则从池里移除.
      candidate.noNewExchanges()

      // Make sure we have some routes left to try. One example where we may exhaust all the routes
      // would happen if we made a new connection and it immediately is detected as unhealthy.
      if (nextRouteToTry != null) continue

      val routesLeft = routeSelection?.hasNext() ?: true
      if (routesLeft) continue

      val routesSelectionLeft = routeSelector?.hasNext() ?: true
      if (routesSelectionLeft) continue

      throw IOException("exhausted all routes")
    }
  }
```
看看核心方法 `findConnection`  优先从已有的连接中找，其次从池里，最后新建一个连接。
``` kotlin
fun findConnection(
    connectTimeout: Int,
    readTimeout: Int,
    writeTimeout: Int,
    pingIntervalMillis: Int,
    connectionRetryEnabled: Boolean
  ): RealConnection {
    if (call.isCanceled()) throw IOException("Canceled")

    // 1.尝试从当前 Call 中复用连接，如果找到则返回
    val callConnection = call.connection // This may be mutated by releaseConnectionNoEvents()!
    if (callConnection != null) {
      var toClose: Socket? = null
      synchronized(callConnection) {
        if (callConnection.noNewExchanges || !sameHostAndPort(callConnection.route().address.url)) {
          toClose = call.releaseConnectionNoEvents()
        }
      }

      // 如果当前 call 中的 connection 尚未释放，那就重用它。
      if (call.connection != null) {
        check(toClose == null)
        return callConnection
      }

      // 如果当前 call 中的 connection 已经释放，那就关闭 socket。并调用释放回调
      toClose?.closeQuietly()
      eventListener.connectionReleased(call, callConnection)
    }

    // 需要一个新连接，重置一些参数
    refusedStreamCount = 0
    connectionShutdownCount = 0
    otherFailureCount = 0

    // 2. 尝试从连接池中获取一个连接。如果找到则返回，否则继续
    if (connectionPool.callAcquirePooledConnection(address, call, null, false)) {
      val result = call.connection!!
      eventListener.connectionAcquired(call, result)
      return result
    }

	// 连接池中未找到，那就找到接下来要尝试的路由
    val routes: List<Route>?
    val route: Route
    if (nextRouteToTry != null) {
      // 使用之前合并连接里的路由
      routes = null
      route = nextRouteToTry!!
      nextRouteToTry = null
    } else if (routeSelection != null && routeSelection!!.hasNext()) {
      // 使用已有路由选择器里的路由
      routes = null
      route = routeSelection!!.next()
    } else {
      // 计算出一个新的路由选择，是一个阻塞操作
      var localRouteSelector = routeSelector
      if (localRouteSelector == null) {
        localRouteSelector = RouteSelector(address, call.client.routeDatabase, call, eventListener)
        this.routeSelector = localRouteSelector
      }
      val localRouteSelection = localRouteSelector.next()
      routeSelection = localRouteSelection
      routes = localRouteSelection.routes

      if (call.isCanceled()) throw IOException("Canceled")
      
      // 3. 现在我们有了一组 IP 地址，再次尝试从连接池中获取连接。由于连接合并，我们有更好的匹配机会。如果找到则返回，否则继续
      if (connectionPool.callAcquirePooledConnection(address, call, routes, false)) {
        val result = call.connection!!
        eventListener.connectionAcquired(call, result)
        return result
      }

      route = localRouteSelection.next()
    }

    // Connect. Tell the call about the connecting call so async cancels work.
    // 4. 若上述都未找到，则新建一个连接。
    val newConnection = RealConnection(connectionPool, route)
    call.connectionToCancel = newConnection
    try {
      newConnection.connect(
          connectTimeout,
          readTimeout,
          writeTimeout,
          pingIntervalMillis,
          connectionRetryEnabled,
          call,
          eventListener
      )
    } finally {
      call.connectionToCancel = null
    }
    call.client.routeDatabase.connected(newConnection.route())

    // 如果我们将另一个呼叫连接到此主机，请合并连接。这使得连接池中有 3 种不同的查找！从连接池中找，带 HTTP/2 的多路复用。
    if (connectionPool.callAcquirePooledConnection(address, call, routes, true)) {
      val result = call.connection!!
      nextRouteToTry = route
      newConnection.socket().closeQuietly()
      eventListener.connectionAcquired(call, result)
      return result
    }
	// 添加新连接到池里
    synchronized(newConnection) {
      connectionPool.put(newConnection)
      call.acquireConnectionNoEvents(newConnection)
    }

    eventListener.connectionAcquired(call, newConnection)
    return newConnection
  }
```
接下来看看连接是如何成功创建连接的
```kotlin
newConnection.connect()
```
``` kotlin
fun connect(
    connectTimeout: Int,
    readTimeout: Int,
    writeTimeout: Int,
    pingIntervalMillis: Int,
    connectionRetryEnabled: Boolean,
    call: Call,
    eventListener: EventListener
  ) {
    check(protocol == null) { "already connected" }

    var routeException: RouteException? = null
    val connectionSpecs = route.address.connectionSpecs
    val connectionSpecSelector = ConnectionSpecSelector(connectionSpecs)

    if (route.address.sslSocketFactory == null) {
      if (ConnectionSpec.CLEARTEXT !in connectionSpecs) {
        throw RouteException(UnknownServiceException(
            "CLEARTEXT communication not enabled for client"))
      }
      val host = route.address.url.host
      if (!Platform.get().isCleartextTrafficPermitted(host)) {
        throw RouteException(UnknownServiceException(
            "CLEARTEXT communication to $host not permitted by network security policy"))
      }
    } else {
      if (Protocol.H2_PRIOR_KNOWLEDGE in route.address.protocols) {
        throw RouteException(UnknownServiceException(
            "H2_PRIOR_KNOWLEDGE cannot be used with HTTPS"))
      }
    }

    while (true) {
      try {
      	// 如果是HTTPS，并且设置了 HTTP 代理，那么就需要建立代理隧道
        if (route.requiresTunnel()) {
          connectTunnel(connectTimeout, readTimeout, writeTimeout, call, eventListener)
          if (rawSocket == null) {
            // 隧道建立失败
            break
          }
        } else {
        // 正常建立 socket 连接
          connectSocket(connectTimeout, readTimeout, call, eventListener)
        }
        // 建立协议
        establishProtocol(connectionSpecSelector, pingIntervalMillis, call, eventListener)
        eventListener.connectEnd(call, route.socketAddress, route.proxy, protocol)
        break
      } catch (e: IOException) {
        socket?.closeQuietly()
        rawSocket?.closeQuietly()
        socket = null
        rawSocket = null
        source = null
        sink = null
        handshake = null
        protocol = null
        http2Connection = null
        allocationLimit = 1

        eventListener.connectFailed(call, route.socketAddress, route.proxy, null, e)

        if (routeException == null) {
          routeException = RouteException(e)
        } else {
          routeException.addConnectException(e)
        }

        if (!connectionRetryEnabled || !connectionSpecSelector.connectionFailed(e)) {
          throw routeException
        }
      }
    }

    if (route.requiresTunnel() && rawSocket == null) {
      throw RouteException(ProtocolException(
          "Too many tunnel connections attempted: $MAX_TUNNEL_ATTEMPTS"))
    }

    idleAtNs = System.nanoTime()
  }
```
接下来看看协议建立过程，当前是 HTTPS 的话建立 TLS 连接，是 HTTP 的话直接返回
```kotlin
fun establishProtocol(
    connectionSpecSelector: ConnectionSpecSelector,
    pingIntervalMillis: Int,
    call: Call,
    eventListener: EventListener
  ) {
  	// 根据 sslSocketFactory 是否为 null 来判断是否是 https
  	// 其值是在 RetryAndFollowUpInterceptor 中赋值的
    if (route.address.sslSocketFactory == null) {
      if (Protocol.H2_PRIOR_KNOWLEDGE in route.address.protocols) {
        socket = rawSocket
        protocol = Protocol.H2_PRIOR_KNOWLEDGE
        startHttp2(pingIntervalMillis)
        return
      }

	 // HTTP 1.1 直接返回 明文通信
      socket = rawSocket
      protocol = Protocol.HTTP_1_1
      return
    }

    eventListener.secureConnectStart(call)
    // TLS 连接开始建立
    connectTls(connectionSpecSelector)
    eventListener.secureConnectEnd(call, handshake)

    if (protocol === Protocol.HTTP_2) {
      startHttp2(pingIntervalMillis)
    }
  }
```
至此，连接建立成功。回到 `find()` 方法，而后创建 `ExchangeCodec` ，用于编码 HTTP 请求和解码响应。
``` kotlin
resultConnection.newCodec(client, chain)
```
``` kotlin
fun newCodec(client: OkHttpClient, chain: RealInterceptorChain): ExchangeCodec {
    val socket = this.socket!!
    val source = this.source!!
    val sink = this.sink!!
    val http2Connection = this.http2Connection

    return if (http2Connection != null) {
      Http2ExchangeCodec(client, this, chain, http2Connection)
    } else {
      socket.soTimeout = chain.readTimeoutMillis()
      source.timeout().timeout(chain.readTimeoutMillis.toLong(), MILLISECONDS)
      sink.timeout().timeout(chain.writeTimeoutMillis.toLong(), MILLISECONDS)
      Http1ExchangeCodec(client, this, source, sink)
    }
  }
```
返回到 `initExchange()` 方法中
``` kotlin
 	val codec = exchangeFinder.find(client, chain)
    val result = Exchange(this, eventListener, exchangeFinder, codec)
```
获得 `codec` 后又生成一个 `Exchange`
再返回到 `ConnectInterceptor` 中，根据创建的 `Exchange` 复制一个新的 `Chain` 链，并调用链上的下一个拦截器 
至此，`ConnectInterceptor` 结束。

#### CallServerInterceptor
这是责任链上的最后一个拦截器，它向服务器进行最终的网络请求。
``` kotlin
 fun intercept(chain: Interceptor.Chain): Response {
    val realChain = chain as RealInterceptorChain
    val exchange = realChain.exchange!!
    val request = realChain.request
    val requestBody = request.body
    val sentRequestMillis = System.currentTimeMillis()

    var invokeStartEvent = true
    var responseBuilder: Response.Builder? = null
    var sendRequestException: IOException? = null
    try {
      // 写入请求头部
      exchange.writeRequestHeaders(request)
	  // 写入请求 body
	  // 仅在请求方法支持 body 时，即不是 GET 或 HEAD 请求。
      if (HttpMethod.permitsRequestBody(request.method) && requestBody != null) {
        // If there's a "Expect: 100-continue" header on the request, wait for a "HTTP/1.1 100
        // Continue" response before transmitting the request body. If we don't get that, return
        // what we did get (such as a 4xx response) without ever transmitting the request body.
        if ("100-continue".equals(request.header("Expect"), ignoreCase = true)) {
          exchange.flushRequest()
          responseBuilder = exchange.readResponseHeaders(expectContinue = true)
          exchange.responseHeadersStart()
          invokeStartEvent = false
        }
        if (responseBuilder == null) {
          if (requestBody.isDuplex()) {
            // Prepare a duplex body so that the application can send a request body later.
            exchange.flushRequest()
            val bufferedRequestBody = exchange.createRequestBody(request, true).buffer()
            requestBody.writeTo(bufferedRequestBody)
          } else {
            // Write the request body if the "Expect: 100-continue" expectation was met.
            val bufferedRequestBody = exchange.createRequestBody(request, false).buffer()
            requestBody.writeTo(bufferedRequestBody)
            bufferedRequestBody.close()
          }
        } else {
          exchange.noRequestBody()
          if (!exchange.connection.isMultiplexed) {
            // If the "Expect: 100-continue" expectation wasn't met, prevent the HTTP/1 connection
            // from being reused. Otherwise we're still obligated to transmit the request body to
            // leave the connection in a consistent state.
            exchange.noNewExchangesOnConnection()
          }
        }
      } else {
        exchange.noRequestBody()
      }

      if (requestBody == null || !requestBody.isDuplex()) {
        exchange.finishRequest()
      }
    } catch (e: IOException) {
      if (e is ConnectionShutdownException) {
        throw e // No request was sent so there's no response to read.
      }
      if (!exchange.hasFailure) {
        throw e // Don't attempt to read the response; we failed to send the request.
      }
      sendRequestException = e
    }
	// 读取响应头部 Response 
    try {
      if (responseBuilder == null) {
        responseBuilder = exchange.readResponseHeaders(expectContinue = false)!!
        if (invokeStartEvent) {
          exchange.responseHeadersStart()
          invokeStartEvent = false
        }
      }
      var response = responseBuilder
          .request(request)
          .handshake(exchange.connection.handshake())
          .sentRequestAtMillis(sentRequestMillis)
          .receivedResponseAtMillis(System.currentTimeMillis())
          .build()
      var code = response.code

      if (shouldIgnoreAndWaitForRealResponse(code)) {
        responseBuilder = exchange.readResponseHeaders(expectContinue = false)!!
        if (invokeStartEvent) {
          exchange.responseHeadersStart()
        }
        response = responseBuilder
            .request(request)
            .handshake(exchange.connection.handshake())
            .sentRequestAtMillis(sentRequestMillis)
            .receivedResponseAtMillis(System.currentTimeMillis())
            .build()
        code = response.code
      }

      exchange.responseHeadersEnd(response)

	  // 读取响应 body
      response = if (forWebSocket && code == 101) {
        // Connection is upgrading, but we need to ensure interceptors see a non-null response body.
        response.newBuilder()
            .body(EMPTY_RESPONSE)
            .build()
      } else {
        response.newBuilder()
            .body(exchange.openResponseBody(response))
            .build()
      }
      if ("close".equals(response.request.header("Connection"), ignoreCase = true) ||
          "close".equals(response.header("Connection"), ignoreCase = true)) {
        exchange.noNewExchangesOnConnection()
      }
      if ((code == 204 || code == 205) && response.body?.contentLength() ?: -1L > 0L) {
        throw ProtocolException(
            "HTTP $code had non-zero Content-Length: ${response.body?.contentLength()}")
      }
      return response
    } catch (e: IOException) {
      if (sendRequestException != null) {
        sendRequestException.addSuppressed(e)
        throw sendRequestException
      }
      throw e
    }
  }
```

最后总结一张图

![okhttp_overview](https://raw.githubusercontent.com/Yunme/Note/main/2024/03/upgit_20240320_1710933993.jpg)
