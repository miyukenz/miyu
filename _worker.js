// <!--GAMFC-->version base on commit 43fad05dcdae3b723c53c226f8181fc5bd47223e, time is 2024-10-21 14:06:14 UTC<!--GAMFC-END-->.
// @ts-ignore
import { connect } from 'cloudflare:sockets';

// How to generate your own UUID:
// [Windows] Press "Win + R", input cmd and run:  Powershell -NoExit -Command "[guid]::NewGuid()"
let userID = '2a94f35a-7ccc-5c81-b74f-766c71f788d5';

let proxyIP = '';// 小白勿动，该地址并不影响你的网速，这是给CF代理使用的。'cdn.xn--b6gac.eu.org, cdn-all.xn--b6gac.eu.org'

let sub = '';// 避免项目被滥用，现已取消内置订阅器
let subconverter = 'SUBAPI.fxxk.dedyn.io';// clash订阅转换后端，目前使用CM的订阅转换功能。自带虚假uuid和host订阅。
let subconfig = "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Mini_MultiMode.ini"; //订阅配置文件
let subProtocol = 'https';
// The user name and password do not contain special characters
// Setting the address will ignore proxyIP
// Example:  user:pass@host:port  or  host:port
let socks5Address = '';

if (!isValidUUID(userID)) {
	throw new Error('uuid is not valid');
}

let parsedSocks5Address = {}; 
let enableSocks = false;

// 虚假uuid和hostname，用于发送给配置生成服务
let fakeUserID ;
let fakeHostName ;
let noTLS = 'false'; 
const expire = 4102329600;//2099-12-31
let proxyIPs;
let socks5s;
let go2Socks5s = [
	'*ttvnw.net',
	'*tapecontent.net',
	'*cloudatacdn.com',
	'*.loadshare.org',
];
let addresses = [
	//当sub为空时启用本地优选域名/优选IP，若不带端口号 TLS默认端口为443，#号后为备注别名
	/*
	'Join.my.Telegram.channel.CMLiussss.to.unlock.more.premium.nodes.cf.090227.xyz#加入我的频道t.me/CMLiussss解锁更多优选节点',
	'visa.cn:443',
	'www.visa.com:8443',
	'cis.visa.com:2053',
	'africa.visa.com:2083',
	'www.visa.com.sg:2087',
	'www.visaeurope.at:2096',
	'www.visa.com.mt:8443',
	'qa.visamiddleeast.com',
	'time.is',
	'www.wto.org:8443',
	'chatgpt.com:2087',
	'icook.hk',
	'104.17.0.0#IPv4',
	'[2606:4700::]#IPv6'
	*/
];
let addressesapi = [];
let addressesnotls = [
	//当sub为空且域名带有"worker"字样时启用本地优选域名/优选IP，若不带端口号 noTLS默认端口为80，#号后为备注别名
	/*
	'usa.visa.com',
	'myanmar.visa.com:8080',
	'www.visa.com.tw:8880',
	'www.visaeurope.ch:2052',
	'www.visa.com.br:2082',
	'www.visasoutheasteurope.com:2086',
	'[2606:4700::1]:2095#IPv6'
	*/
];
let addressesnotlsapi = [];
let addressescsv = [];
let DLS = 8;
let FileName = 'edgetunnel';
let BotToken ='';
let ChatID =''; 
let proxyhosts = [];//本地代理域名池
let proxyhostsURL = 'https://raw.githubusercontent.com/cmliu/CFcdnVmess2sub/main/proxyhosts';//在线代理域名池URL
let RproxyIP = 'false';
let httpsPorts = ["2053","2083","2087","2096","8443"];
let effectiveTime = 7;//有效时间 单位:天
let updateTime = 3;//更新时间
let userIDLow;
let userIDTime = "";
export default {
	/**
	 * @param {import("@cloudflare/workers-types").Request} request
	 * @param {{UUID: string, PROXYIP: string}} env
	 * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
	 * @returns {Promise<Response>}
	 */
	async fetch(request, env, ctx) {
		try {
			const UA = request.headers.get('User-Agent') || 'null';
			const userAgent = UA.toLowerCase();
			userID = (env.UUID || userID).toLowerCase();

			const currentDate = new Date();
			currentDate.setHours(0, 0, 0, 0); 
			const timestamp = Math.ceil(currentDate.getTime() / 1000);
			const fakeUserIDMD5 = await MD5MD5(`${userID}${timestamp}`);
			fakeUserID = fakeUserIDMD5.slice(0, 8) + "-" + fakeUserIDMD5.slice(8, 12) + "-" + fakeUserIDMD5.slice(12, 16) + "-" + fakeUserIDMD5.slice(16, 20) + "-" + fakeUserIDMD5.slice(20);
			fakeHostName = fakeUserIDMD5.slice(6, 9) + "." + fakeUserIDMD5.slice(13, 19);
			//console.log(`虚假UUID: ${fakeUserID}`); // 打印fakeID
			if (env.KEY) {
				const userIDs = await generateDynamicUUID(env.KEY);
				userID = userIDs[0];
				userIDLow = userIDs[1];
				userIDTime = userIDs[2];
				//console.log(`启用动态UUID\n秘钥KEY: ${env.KEY}\nUUIDNow: ${userID}\nUUIDLow: ${userIDLow}`);
				effectiveTime = env.TIME || effectiveTime;
				updateTime = env.UPTIME || updateTime;
			}
			proxyIP = env.PROXYIP || proxyIP;
			proxyIPs = await ADD(proxyIP);
			proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
			//console.log(proxyIP);
			socks5Address = env.SOCKS5 || socks5Address;
			socks5s = await ADD(socks5Address);
			socks5Address = socks5s[Math.floor(Math.random() * socks5s.length)];
			socks5Address = socks5Address.split('//')[1] || socks5Address;
			if (env.CFPORTS) httpsPorts = await ADD(env.CFPORTS);
			sub = env.SUB || sub;
			subconverter = env.SUBAPI || subconverter;
			if( subconverter.includes("http://") ){
				subconverter = subconverter.split("//")[1];
				subProtocol = 'http';
			} else {
				subconverter = subconverter.split("//")[1] || subconverter;
			}
			subconfig = env.SUBCONFIG || subconfig;
			if (socks5Address) {
				try {
					parsedSocks5Address = socks5AddressParser(socks5Address);
					RproxyIP = env.RPROXYIP || 'false';
					enableSocks = true;
				} catch (err) {
  					/** @type {Error} */ 
					let e = err;
					console.log(e.toString());
					RproxyIP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
					enableSocks = false;
				}
			} else {
				RproxyIP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
			}
			if (env.ADD) addresses = await ADD(env.ADD);
			if (env.ADDAPI) addressesapi = await ADD(env.ADDAPI);
			if (env.ADDNOTLS) addressesnotls = await ADD(env.ADDNOTLS);
			if (env.ADDNOTLSAPI) addressesnotlsapi = await ADD(env.ADDNOTLSAPI);
			if (env.ADDCSV) addressescsv = await ADD(env.ADDCSV);
			DLS = env.DLS || DLS;
			BotToken = env.TGTOKEN || BotToken;
			ChatID = env.TGID || ChatID; 
			if(env.GO2SOCKS5) go2Socks5s = await ADD(env.GO2SOCKS5);
			const upgradeHeader = request.headers.get('Upgrade');
			const url = new URL(request.url);
			if (url.searchParams.has('sub') && url.searchParams.get('sub') !== '') sub = url.searchParams.get('sub');
			FileName = env.SUBNAME || FileName;
			if (url.searchParams.has('notls')) noTLS = 'true';
			if (!upgradeHeader || upgradeHeader !== 'websocket') {
				const 路径 = url.pathname.toLowerCase();
				if (路径 == '/') {
					if (env.URL302) return Response.redirect(env.URL302, 302);
					else if (env.URL) return await proxyURL(env.URL, url);
					else return new Response(JSON.stringify(request.cf, null, 4), {
						status: 200,
						headers: {
							'content-type': 'application/json',
						},
					});
				} else if (路径 == `/${fakeUserID}`) {
					const fakeConfig = await getVLESSConfig(userID, request.headers.get('Host'), sub, 'CF-Workers-SUB', RproxyIP, url, env);
					return new Response(`${fakeConfig}`, { status: 200 });
				} else if (路径 == `/${env.KEY}` || 路径 == `/${userID}`) {
					await sendMessage(`#获取订阅 ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${UA}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search}</tg-spoiler>`);
					const vlessConfig = await getVLESSConfig(userID, request.headers.get('Host'), sub, UA, RproxyIP, url, env);
					const now = Date.now();
					//const timestamp = Math.floor(now / 1000);
					const today = new Date(now);
					today.setHours(0, 0, 0, 0);
					const UD = Math.floor(((now - today.getTime())/86400000) * 24 * 1099511627776 / 2);
					let pagesSum = UD;
					let workersSum = UD;
					let total = 24 * 1099511627776 ;
					if (env.CFEMAIL && env.CFKEY){
						const email = env.CFEMAIL;
						const key = env.CFKEY;
						const accountIndex = env.CFID || 0;
						const accountId = await getAccountId(email, key);
						if (accountId){
							const now = new Date()
							now.setUTCHours(0, 0, 0, 0)
							const startDate = now.toISOString()
							const endDate = new Date().toISOString();
							const Sum = await getSum(accountId, accountIndex, email, key, startDate, endDate);
							pagesSum = Sum[0];
							workersSum = Sum[1];
							total = 102400 ;
						}
					}
					//console.log(`pagesSum: ${pagesSum}\nworkersSum: ${workersSum}\ntotal: ${total}`);
					if (userAgent && userAgent.includes('mozilla')){
						return new Response(`${vlessConfig}`, {
							status: 200,
							headers: {
								"Content-Type": "text/plain;charset=utf-8",
								"Profile-Update-Interval": "6",
								"Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
							}
						});
					} else {
						return new Response(`${vlessConfig}`, {
							status: 200,
							headers: {
								"Content-Disposition": `attachment; filename=${FileName}; filename*=utf-8''${encodeURIComponent(FileName)}`,
								"Content-Type": "text/plain;charset=utf-8",
								"Profile-Update-Interval": "6",
								"Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
							}
						});
					}
				} else {
					if (env.URL302) return Response.redirect(env.URL302, 302);
					else if (env.URL) return await proxyURL(env.URL, url);
					else return new Response('不用怀疑！你UUID就是错的！！！', { status: 404 });
				}
			} else {
				proxyIP = url.searchParams.get('proxyip') || proxyIP;
				if (new RegExp('/proxyip=', 'i').test(url.pathname)) proxyIP = url.pathname.toLowerCase().split('/proxyip=')[1];
				else if (new RegExp('/proxyip.', 'i').test(url.pathname)) proxyIP = `proxyip.${url.pathname.toLowerCase().split("/proxyip.")[1]}`;
				
				socks5Address = url.searchParams.get('socks5') || socks5Address;
				if (new RegExp('/socks5=', 'i').test(url.pathname)) socks5Address = url.pathname.split('5=')[1];
				else if (new RegExp('/socks://', 'i').test(url.pathname) || new RegExp('/socks5://', 'i').test(url.pathname)) {
					socks5Address = url.pathname.split('://')[1].split('#')[0];
					if (socks5Address.includes('@')){
						let userPassword = socks5Address.split('@')[0];
						const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
						if (base64Regex.test(userPassword) && !userPassword.includes(':')) userPassword = atob(userPassword);
						socks5Address = `${userPassword}@${socks5Address.split('@')[1]}`;
					}
				}
				if (socks5Address) {
					try {
						parsedSocks5Address = socks5AddressParser(socks5Address);
						enableSocks = true;
					} catch (err) {
						/** @type {Error} */ 
						let e = err;
						console.log(e.toString());
						enableSocks = false;
					}
				} else {
					enableSocks = false;
				}

				return await vlessOverWSHandler(request);
			}
		} catch (err) {
			/** @type {Error} */ let e = err;
			return new Response(e.toString());
		}
	},
};

/**
 * 处理 VLESS over WebSocket 的请求
 * @param {import("@cloudflare/workers-types").Request} request
 */
async function vlessOverWSHandler(request) {

	/** @type {import("@cloudflare/workers-types").WebSocket[]} */
	// @ts-ignore
	const webSocketPair = new WebSocketPair();
	const [client, webSocket] = Object.values(webSocketPair);

	// 接受 WebSocket 连接
	webSocket.accept();

	let address = '';
	let portWithRandomLog = '';
	// 日志函数，用于记录连接信息
	const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
		console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
	};
	// 获取早期数据头部，可能包含了一些初始化数据
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

	// 创建一个可读的 WebSocket 流，用于接收客户端数据
	const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

	/** @type {{ value: import("@cloudflare/workers-types").Socket | null}}*/
	// 用于存储远程 Socket 的包装器
	let remoteSocketWapper = {
		value: null,
	};
	// 标记是否为 DNS 查询
	let isDns = false;

	// WebSocket 数据流向远程服务器的管道
	readableWebSocketStream.pipeTo(new WritableStream({
		async write(chunk, controller) {
			if (isDns) {
				// 如果是 DNS 查询，调用 DNS 处理函数
				return await handleDNSQuery(chunk, webSocket, null, log);
			}
			if (remoteSocketWapper.value) {
				// 如果已有远程 Socket，直接写入数据
				const writer = remoteSocketWapper.value.writable.getWriter()
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}

			// 处理 VLESS 协议头部
			const {
				hasError,
				message,
				addressType,
				portRemote = 443,
				addressRemote = '',
				rawDataIndex,
				vlessVersion = new Uint8Array([0, 0]),
				isUDP,
			} = processVlessHeader(chunk, userID);
			// 设置地址和端口信息，用于日志
			address = addressRemote;
			portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '} `;
			if (hasError) {
				// 如果有错误，抛出异常
				throw new Error(message);
				return;
			}
			// 如果是 UDP 且端口不是 DNS 端口（53），则关闭连接
			if (isUDP) {
				if (portRemote === 53) {
					isDns = true;
				} else {
					throw new Error('UDP 代理仅对 DNS（53 端口）启用');
					return;
				}
			}
			// 构建 VLESS 响应头部
			const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
			// 获取实际的客户端数据
			const rawClientData = chunk.slice(rawDataIndex);

			if (isDns) {
				// 如果是 DNS 查询，调用 DNS 处理函数
				return handleDNSQuery(rawClientData, webSocket, vlessResponseHeader, log);
			}
			// 处理 TCP 出站连接
			log(`处理 TCP 出站连接 ${addressRemote}:${portRemote}`);
			handleTCPOutBound(remoteSocketWapper, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log);
		},
		close() {
			log(`readableWebSocketStream 已关闭`);
		},
		abort(reason) {
			log(`readableWebSocketStream 已中止`, JSON.stringify(reason));
		},
	})).catch((err) => {
		log('readableWebSocketStream 管道错误', err);
	});

	// 返回一个 WebSocket 升级的响应
	return new Response(null, {
		status: 101,
		// @ts-ignore
		webSocket: client,
	});
}

/**
 * 处理出站 TCP 连接。
 *
 * @param {any} remoteSocket 远程 Socket 的包装器，用于存储实际的 Socket 对象
 * @param {number} addressType 要连接的远程地址类型（如 IP 类型：IPv4 或 IPv6）
 * @param {string} addressRemote 要连接的远程地址
 * @param {number} portRemote 要连接的远程端口
 * @param {Uint8Array} rawClientData 要写入的原始客户端数据
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket 用于传递远程 Socket 的 WebSocket
 * @param {Uint8Array} vlessResponseHeader VLESS 响应头部
 * @param {function} log 日志记录函数
 * @returns {Promise<void>} 异步操作的 Promise
 */
async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log,) {
	async function useSocks5Pattern(address) {
		if ( go2Socks5s.includes(atob('YWxsIGlu')) || go2Socks5s.includes(atob('Kg==')) ) return true;
		return go2Socks5s.some(pattern => {
			let regexPattern = pattern.replace(/\*/g, '.*');
			let regex = new RegExp(`^${regexPattern}$`, 'i');
			return regex.test(address);
		});
	}
	/**
	 * 连接远程服务器并写入数据
	 * @param {string} address 要连接的地址
	 * @param {number} port 要连接的端口
	 * @param {boolean} socks 是否使用 SOCKS5 代理连接
	 * @returns {Promise<import("@cloudflare/workers-types").Socket>} 连接后的 TCP Socket
	 */
	async function connectAndWrite(address, port, socks = false) {
		/** @type {import("@cloudflare/workers-types").Socket} */
		log(`connected to ${address}:${port}`);
		//if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(address)) address = `${atob('d3d3Lg==')}${address}${atob('LmlwLjA5MDIyNy54eXo=')}`;
		// 如果指定使用 SOCKS5 代理，则通过 SOCKS5 协议连接；否则直接连接
		const tcpSocket = socks ? await socks5Connect(addressType, address, port, log)
			: connect({
				hostname: address,
				port: port,
			});
		remoteSocket.value = tcpSocket;
		//log(`connected to ${address}:${port}`);
		const writer = tcpSocket.writable.getWriter();
		// 首次写入，通常是 TLS 客户端 Hello 消息
		await writer.write(rawClientData);
		writer.releaseLock();
		return tcpSocket;
	}

	/**
	 * 重试函数：当 Cloudflare 的 TCP Socket 没有传入数据时，我们尝试重定向 IP
	 * 这可能是因为某些网络问题导致的连接失败
	 */
	async function retry() {
		if (enableSocks) {
			// 如果启用了 SOCKS5，通过 SOCKS5 代理重试连接
			tcpSocket = await connectAndWrite(addressRemote, portRemote, true);
		} else {
			// 否则，尝试使用预设的代理 IP（如果有）或原始地址重试连接
			if (!proxyIP || proxyIP == '') {
				proxyIP = atob('cHJveHlpcC50cDEuY21saXVzc3NzLmNvbQ==');
			} else if (proxyIP.includes(']:')) {
				portRemote = proxyIP.split(']:')[1] || portRemote;
				proxyIP = proxyIP.split(']:')[0] || proxyIP;
			} else if (proxyIP.split(':').length === 2) {
				portRemote = proxyIP.split(':')[1] || portRemote;
				proxyIP = proxyIP.split(':')[0] || proxyIP;
			}
			if (proxyIP.includes('.tp')) portRemote = proxyIP.split('.tp')[1].split('.')[0] || portRemote;
			tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote);
		}
		// 无论重试是否成功，都要关闭 WebSocket（可能是为了重新建立连接）
		tcpSocket.closed.catch(error => {
			console.log('retry tcpSocket closed error', error);
		}).finally(() => {
			safeCloseWebSocket(webSocket);
		})
		// 建立从远程 Socket 到 WebSocket 的数据流
		remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
	}

	let useSocks = false;
	if( go2Socks5s.length > 0 && enableSocks ) useSocks = await useSocks5Pattern(addressRemote);
	// 首次尝试连接远程服务器
	let tcpSocket = await connectAndWrite(addressRemote, portRemote, useSocks);

	// 当远程 Socket 就绪时，将其传递给 WebSocket
	// 建立从远程服务器到 WebSocket 的数据流，用于将远程服务器的响应发送回客户端
	// 如果连接失败或无数据，retry 函数将被调用进行重试
	remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
}

/**
 * 将 WebSocket 转换为可读流（ReadableStream）
 * @param {import("@cloudflare/workers-types").WebSocket} webSocketServer 服务器端的 WebSocket 对象
 * @param {string} earlyDataHeader WebSocket 0-RTT（零往返时间）的早期数据头部
 * @param {(info: string)=> void} log 日志记录函数，用于记录 WebSocket 0-RTT 相关信息
 * @returns {ReadableStream} 由 WebSocket 消息组成的可读流
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
	// 标记可读流是否已被取消
	let readableStreamCancel = false;

	// 创建一个新的可读流
	const stream = new ReadableStream({
		// 当流开始时的初始化函数
		start(controller) {
			// 监听 WebSocket 的消息事件
			webSocketServer.addEventListener('message', (event) => {
				// 如果流已被取消，不再处理新消息
				if (readableStreamCancel) {
					return;
				}
				const message = event.data;
				// 将消息加入流的队列中
				controller.enqueue(message);
			});

			// 监听 WebSocket 的关闭事件
			// 注意：这个事件意味着客户端关闭了客户端 -> 服务器的流
			// 但是，服务器 -> 客户端的流仍然打开，直到在服务器端调用 close()
			// WebSocket 协议要求在每个方向上都要发送单独的关闭消息，以完全关闭 Socket
			webSocketServer.addEventListener('close', () => {
				// 客户端发送了关闭信号，需要关闭服务器端
				safeCloseWebSocket(webSocketServer);
				// 如果流未被取消，则关闭控制器
				if (readableStreamCancel) {
					return;
				}
				controller.close();
			});

			// 监听 WebSocket 的错误事件
			webSocketServer.addEventListener('error', (err) => {
				log('WebSocket 服务器发生错误');
				// 将错误传递给控制器
				controller.error(err);
			});

			// 处理 WebSocket 0-RTT（零往返时间）的早期数据
			// 0-RTT 允许在完全建立连接之前发送数据，提高了效率
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				// 如果解码早期数据时出错，将错误传递给控制器
				controller.error(error);
			} else if (earlyData) {
				// 如果有早期数据，将其加入流的队列中
				controller.enqueue(earlyData);
			}
		},

		// 当使用者从流中拉取数据时调用
		pull(controller) {
			// 这里可以实现反压机制
			// 如果 WebSocket 可以在流满时停止读取，我们就可以实现反压
			// 参考：https://streams.spec.whatwg.org/#example-rs-push-backpressure
		},

		// 当流被取消时调用
		cancel(reason) {
			// 流被取消的几种情况：
			// 1. 当管道的 WritableStream 有错误时，这个取消函数会被调用，所以在这里处理 WebSocket 服务器的关闭
			// 2. 如果 ReadableStream 被取消，所有 controller.close/enqueue 都需要跳过
			// 3. 但是经过测试，即使 ReadableStream 被取消，controller.error 仍然有效
			if (readableStreamCancel) {
				return;
			}
			log(`可读流被取消，原因是 ${reason}`);
			readableStreamCancel = true;
			// 安全地关闭 WebSocket
			safeCloseWebSocket(webSocketServer);
		}
	});

	return stream;
}

// https://xtls.github.io/development/protocols/vless.html
// https://github.com/zizifn/excalidraw-backup/blob/main/v2ray-protocol.excalidraw

/**
 * 解析 VLESS 协议的头部数据
 * @param { ArrayBuffer} vlessBuffer VLESS 协议的原始头部数据
 * @param {string} userID 用于验证的用户 ID
 * @returns {Object} 解析结果，包括是否有错误、错误信息、远程地址信息等
 */
function processVlessHeader(vlessBuffer, userID) {
	// 检查数据长度是否足够（至少需要 24 字节）
	if (vlessBuffer.byteLength < 24) {
		return {
			hasError: true,
			message: 'invalid data',
		};
	}

	// 解析 VLESS 协议版本（第一个字节）
	const version = new Uint8Array(vlessBuffer.slice(0, 1));

	let isValidUser = false;
	let isUDP = false;

	// 验证用户 ID（接下来的 16 个字节）
	function isUserIDValid(userID, userIDLow, buffer) {
		const userIDArray = new Uint8Array(buffer.slice(1, 17));
		const userIDString = stringify(userIDArray);
		return userIDString === userID || userIDString === userIDLow;
	}

	// 使用函数验证
	isValidUser = isUserIDValid(userID, userIDLow, vlessBuffer);

	// 如果用户 ID 无效
