// src/worker.js
import { connect } from "cloudflare:sockets";
// 设置明文密码
let password = 'cacm'; 
let sha224Password ;
//设置伪装web
let proxydomain = 'www.bing.com';
//设置proxyIP
let proxyIP = 'proxyip.fxxk.dedyn.io';
let RproxyIP = 'true';//设为true则强制使用订阅器内置的proxyIP
//内置订阅器嵌套
let sub = 'sub.xmm404.workers.dev';//订阅器
let subconverter = 'apiurl.v1.mk';//转换后端
let subconfig = 'https://raw.githubusercontent.com/JustLagom/test/main/urltestconfig.ini';//配置文件config

/*
if (!isValidSHA224(sha224Password)) {
    throw new Error('sha224Password is not valid');
}
*/
export default {
    /**
     * @param {import("@cloudflare/workers-types").Request} request
     * @param {{PASSWORD, SHA224, SHA224PASS, PROXYIP, PROXYDOMAIN, RPROXYIP, SUB, SUBAPI, SUBCONFIG: string}} env
     * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
     * @returns {Promise<Response>}
     */
    async fetch(request, env, ctx) {
        try {
            password = env.PASSWORD || password;
            sha224Password = env.SHA224 || env.SHA224PASS || sha256.sha224(password);
            proxydomain = env.PROXYDOMAIN || proxydomain;
            RproxyIP = env.RPROXYIP || RproxyIP;
            proxyIP = env.PROXYIP || proxyIP;
            sub = env.SUB || sub;
            subconverter = env.SUBAPI || subconverter;
            subconfig = env.SUBCONFIG || subconfig;
            const UA = request.headers.get('User-Agent') || 'null';
            const userAgent = UA.toLowerCase();
            const upgradeHeader = request.headers.get("Upgrade");
            const url = new URL(request.url);
            if (!upgradeHeader || upgradeHeader !== "websocket") {
                //const url = new URL(request.url);
                switch (url.pathname.toLowerCase()) {
                    case `/${password}`: {
                        const trojanConfig = await getTROJANConfig(password, request.headers.get('Host'), sub, UA, RproxyIP, url);
                        return new Response(`${trojanConfig}`, {
                        	status: 200,
                        	headers: {
                        		"Content-Type": "text/plain;charset=utf-8",
                        	}
                        });
                    } 
                    default:
                         url.hostname = proxydomain;
                         url.protocol = 'https:';
                         request = new Request(url, request);
                         return await fetch(request);
                      }
            } else {
                // 从查询字符串中获取'proxyip'参数
                proxyIP = url.searchParams.get('proxyIP') || proxyIP;
                if (new RegExp('/proxyIP=', 'i').test(url.pathname)) proxyIP = url.pathname.toLowerCase().split('/proxyIP=')[1];
                else if (new RegExp('/proxyIP.', 'i').test(url.pathname)) proxyIP = `proxyIP.${url.pathname.toLowerCase().split("/proxyIP.")[1]}`;
		else if (!proxyIP || proxyIP == '') proxyIP = 'proxyip.fxxk.dedyn.io';
                return await trojanOverWSHandler(request);
            }
        } catch (err) {
            let e = err;
            return new Response(e.toString());
        }
    }
};

async function trojanOverWSHandler(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();
    let address = "";
    let portWithRandomLog = "";
    const log = (info, event) => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
    };
    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
    let remoteSocketWapper = {
        value: null
    };
    let udpStreamWrite = null;
    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (udpStreamWrite) {
                return udpStreamWrite(chunk);
            }
            if (remoteSocketWapper.value) {
                const writer = remoteSocketWapper.value.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }
            const {
                hasError,
                message,
                portRemote = 443,
                addressRemote = "",
                rawClientData
            } = await parseTrojanHeader(chunk);
            address = addressRemote;
            portWithRandomLog = `${portRemote}--${Math.random()} tcp`;
            if (hasError) {
                throw new Error(message);
                return;
            }
            handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, log);
        },
        close() {
            log(`readableWebSocketStream is closed`);
        },
        abort(reason) {
            log(`readableWebSocketStream is aborted`, JSON.stringify(reason));
        }
    })).catch((err) => {
        log("readableWebSocketStream pipeTo error", err);
    });
    return new Response(null, {
        status: 101,
        // @ts-ignore
        webSocket: client
    });
}

async function parseTrojanHeader(buffer) {
    if (buffer.byteLength < 56) {
        return {
            hasError: true,
            message: "invalid data"
        };
    }
    let crLfIndex = 56;
    if (new Uint8Array(buffer.slice(56, 57))[0] !== 0x0d || new Uint8Array(buffer.slice(57, 58))[0] !== 0x0a) {
        return {
            hasError: true,
            message: "invalid header format (missing CR LF)"
        };
    }
    const password = new TextDecoder().decode(buffer.slice(0, crLfIndex));
    if (password !== sha224Password) {
        return {
            hasError: true,
            message: "invalid password"
        };
    }

    const socks5DataBuffer = buffer.slice(crLfIndex + 2);
    if (socks5DataBuffer.byteLength < 6) {
        return {
            hasError: true,
            message: "invalid SOCKS5 request data"
        };
    }

    const view = new DataView(socks5DataBuffer);
    const cmd = view.getUint8(0);
    if (cmd !== 1) {
        return {
            hasError: true,
            message: "unsupported command, only TCP (CONNECT) is allowed"
        };
    }

    const atype = view.getUint8(1);
    // 0x01: IPv4 address
    // 0x03: Domain name
    // 0x04: IPv6 address
    let addressLength = 0;
    let addressIndex = 2;
    let address = "";
    switch (atype) {
        case 1:
            addressLength = 4;
            address = new Uint8Array(
              socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)
            ).join(".");
            break;
        case 3:
            addressLength = new Uint8Array(
              socks5DataBuffer.slice(addressIndex, addressIndex + 1)
            )[0];
            addressIndex += 1;
            address = new TextDecoder().decode(
              socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)
            );
            break;
        case 4:
            addressLength = 16;
            const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            address = ipv6.join(":");
            break;
        default:
            return {
                hasError: true,
                message: `invalid addressType is ${atype}`
            };
    }

    if (!address) {
        return {
            hasError: true,
            message: `address is empty, addressType is ${atype}`
        };
    }

    const portIndex = addressIndex + addressLength;
    const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    return {
        hasError: false,
        addressRemote: address,
        portRemote,
        rawClientData: socks5DataBuffer.slice(portIndex + 4)
    };
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, log) {
    async function connectAndWrite(address, port) {
        const tcpSocket2 = connect({
            hostname: address,
            port
        });
        remoteSocket.value = tcpSocket2;
        log(`connected to ${address}:${port}`);
        const writer = tcpSocket2.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket2;
    }
    async function retry() {
        const tcpSocket2 = await connectAndWrite(proxyIP || addressRemote, portRemote);
        tcpSocket2.closed.catch((error) => {
            console.log("retry tcpSocket closed error", error);
        }).finally(() => {
            safeCloseWebSocket(webSocket);
        });
        remoteSocketToWS(tcpSocket2, webSocket, null, log);
    }
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    remoteSocketToWS(tcpSocket, webSocket, retry, log);
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener("message", (event) => {
                if (readableStreamCancel) {
                    return;
                }
                const message = event.data;
                controller.enqueue(message);
            });
            webSocketServer.addEventListener("close", () => {
                safeCloseWebSocket(webSocketServer);
                if (readableStreamCancel) {
                    return;
                }
                controller.close();
            });
            webSocketServer.addEventListener("error", (err) => {
                log("webSocketServer error");
                controller.error(err);
            });
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },
        pull(controller) {},
        cancel(reason) {
            if (readableStreamCancel) {
                return;
            }
            log(`readableStream was canceled, due to ${reason}`);
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        }
    });
    return stream;
}

async function remoteSocketToWS(remoteSocket, webSocket, retry, log) {
    let hasIncomingData = false;
    await remoteSocket.readable.pipeTo(
        new WritableStream({
            start() {},
            /**
             *
             * @param {Uint8Array} chunk
             * @param {*} controller
             */
            async write(chunk, controller) {
                hasIncomingData = true;
                if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                    controller.error(
                        "webSocket connection is not open"
                    );
                }
                webSocket.send(chunk);
            },
            close() {
                log(`remoteSocket.readable is closed, hasIncomingData: ${hasIncomingData}`);
            },
            abort(reason) {
                console.error("remoteSocket.readable abort", reason);
            }
        })
    ).catch((error) => {
        console.error(
            `remoteSocketToWS error:`,
            error.stack || error
        );
        safeCloseWebSocket(webSocket);
    });
    if (hasIncomingData === false && retry) {
        log(`retry`);
        retry();
    }
}

/*
function isValidSHA224(hash) {
	const sha224Regex = /^[0-9a-f]{56}$/i;
	return sha224Regex.test(hash);
}
*/

function base64ToArrayBuffer(base64Str) {
    if (!base64Str) {
        return { error: null };
    }
    try {
        base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
        const decode = atob(base64Str);
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        return { error };
    }
}

let WS_READY_STATE_OPEN = 1;
let WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
        console.error("safeCloseWebSocket error", error);
    }
}

/**
 * @param {string} password
 * @param {string | null} hostName
 * @param {string} sub
 * @param {string} UA
 * @returns {Promise<string>}
 */
let subParams = ['sub','base64','b64','clash','singbox','sb'];
async function getTROJANConfig(password, hostName, sub, UA, RproxyIP, _url) {
	const userAgent = UA.toLowerCase();
	if ((!sub || sub === '' || (sub && userAgent.includes('mozilla'))) && !subParams.some(_searchParams => _url.searchParams.has(_searchParams))) {
    return `
    <p>===================================================配置详解=======================================================</p>
      Subscribe / sub 订阅地址, 支持 Base64、clash-meta、sing-box 订阅格式, 您的订阅内容由 ${sub} 提供维护支持, 自动获取ProxyIP: ${RproxyIP}.
    --------------------------------------------------------------------------------------------------------------------
      订阅地址：https://${sub}/sub?host=${hostName}&password=${password}&proxyip=${RproxyIP}
    <p>=================================================================================================================</p>
      github 项目地址 Star!Star!Star!!!
      telegram 交流群 技术大佬~在线发牌!
      https://t.me/CMLiussss
    <p>=================================================================================================================</p>
    `
  }
}

/**
 * [js-sha256]{@link https://github.com/emn178/js-sha256}
 *
 * @version 0.11.0
 * @author Chen, Yi-Cyuan [emn178@gmail.com]
 * @copyright Chen, Yi-Cyuan 2014-2024
 * @license MIT
 */
/*jslint bitwise: true */
(function () {
	'use strict';
  
	var ERROR = 'input is invalid type';
	var WINDOW = typeof window === 'object';
	var root = WINDOW ? window : {};
	if (root.JS_SHA256_NO_WINDOW) {
	  WINDOW = false;
	}
	var WEB_WORKER = !WINDOW && typeof self === 'object';
	var NODE_JS = !root.JS_SHA256_NO_NODE_JS && typeof process === 'object' && process.versions && process.versions.node;
	if (NODE_JS) {
	  root = global;
	} else if (WEB_WORKER) {
	  root = self;
	}
	var COMMON_JS = !root.JS_SHA256_NO_COMMON_JS && typeof module === 'object' && module.exports;
	var AMD = typeof define === 'function' && define.amd;
	var ARRAY_BUFFER = !root.JS_SHA256_NO_ARRAY_BUFFER && typeof ArrayBuffer !== 'undefined';
	var HEX_CHARS = '0123456789abcdef'.split('');
	var EXTRA = [-2147483648, 8388608, 32768, 128];
	var SHIFT = [24, 16, 8, 0];
	var K = [
	  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	];
	var OUTPUT_TYPES = ['hex', 'array', 'digest', 'arrayBuffer'];
  
	var blocks = [];
  
	if (root.JS_SHA256_NO_NODE_JS || !Array.isArray) {
	  Array.isArray = function (obj) {
		return Object.prototype.toString.call(obj) === '[object Array]';
	  };
	}
  
	if (ARRAY_BUFFER && (root.JS_SHA256_NO_ARRAY_BUFFER_IS_VIEW || !ArrayBuffer.isView)) {
	  ArrayBuffer.isView = function (obj) {
		return typeof obj === 'object' && obj.buffer && obj.buffer.constructor === ArrayBuffer;
	  };
	}
  
	var createOutputMethod = function (outputType, is224) {
	  return function (message) {
		return new Sha256(is224, true).update(message)[outputType]();
	  };
	};
  
	var createMethod = function (is224) {
	  var method = createOutputMethod('hex', is224);
	  if (NODE_JS) {
		method = nodeWrap(method, is224);
	  }
	  method.create = function () {
		return new Sha256(is224);
	  };
	  method.update = function (message) {
		return method.create().update(message);
	  };
	  for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
		var type = OUTPUT_TYPES[i];
		method[type] = createOutputMethod(type, is224);
	  }
	  return method;
	};
  
	var nodeWrap = function (method, is224) {
	  var crypto = require('crypto')
	  var Buffer = require('buffer').Buffer;
	  var algorithm = is224 ? 'sha224' : 'sha256';
	  var bufferFrom;
	  if (Buffer.from && !root.JS_SHA256_NO_BUFFER_FROM) {
		bufferFrom = Buffer.from;
	  } else {
		bufferFrom = function (message) {
		  return new Buffer(message);
		};
	  }
	  var nodeMethod = function (message) {
		if (typeof message === 'string') {
		  return crypto.createHash(algorithm).update(message, 'utf8').digest('hex');
		} else {
		  if (message === null || message === undefined) {
			throw new Error(ERROR);
		  } else if (message.constructor === ArrayBuffer) {
			message = new Uint8Array(message);
		  }
		}
		if (Array.isArray(message) || ArrayBuffer.isView(message) ||
		  message.constructor === Buffer) {
		  return crypto.createHash(algorithm).update(bufferFrom(message)).digest('hex');
		} else {
		  return method(message);
		}
	  };
	  return nodeMethod;
	};
  
	var createHmacOutputMethod = function (outputType, is224) {
	  return function (key, message) {
		return new HmacSha256(key, is224, true).update(message)[outputType]();
	  };
	};
  
	var createHmacMethod = function (is224) {
	  var method = createHmacOutputMethod('hex', is224);
	  method.create = function (key) {
		return new HmacSha256(key, is224);
	  };
	  method.update = function (key, message) {
		return method.create(key).update(message);
	  };
	  for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
		var type = OUTPUT_TYPES[i];
		method[type] = createHmacOutputMethod(type, is224);
	  }
	  return method;
	};
  
	function Sha256(is224, sharedMemory) {
	  if (sharedMemory) {
		blocks[0] = blocks[16] = blocks[1] = blocks[2] = blocks[3] =
		  blocks[4] = blocks[5] = blocks[6] = blocks[7] =
		  blocks[8] = blocks[9] = blocks[10] = blocks[11] =
		  blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
		this.blocks = blocks;
	  } else {
		this.blocks = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
	  }
  
	  if (is224) {
		this.h0 = 0xc1059ed8;
		this.h1 = 0x367cd507;
		this.h2 = 0x3070dd17;
		this.h3 = 0xf70e5939;
		this.h4 = 0xffc00b31;
		this.h5 = 0x68581511;
		this.h6 = 0x64f98fa7;
		this.h7 = 0xbefa4fa4;
	  } else { // 256
		this.h0 = 0x6a09e667;
		this.h1 = 0xbb67ae85;
		this.h2 = 0x3c6ef372;
		this.h3 = 0xa54ff53a;
		this.h4 = 0x510e527f;
		this.h5 = 0x9b05688c;
		this.h6 = 0x1f83d9ab;
		this.h7 = 0x5be0cd19;
	  }
  
	  this.block = this.start = this.bytes = this.hBytes = 0;
	  this.finalized = this.hashed = false;
	  this.first = true;
	  this.is224 = is224;
	}
  
	Sha256.prototype.update = function (message) {
	  if (this.finalized) {
		return;
	  }
	  var notString, type = typeof message;
	  if (type !== 'string') {
		if (type === 'object') {
		  if (message === null) {
			throw new Error(ERROR);
		  } else if (ARRAY_BUFFER && message.constructor === ArrayBuffer) {
			message = new Uint8Array(message);
		  } else if (!Array.isArray(message)) {
			if (!ARRAY_BUFFER || !ArrayBuffer.isView(message)) {
			  throw new Error(ERROR);
			}
		  }
		} else {
		  throw new Error(ERROR);
		}
		notString = true;
	  }
	  var code, index = 0, i, length = message.length, bl
