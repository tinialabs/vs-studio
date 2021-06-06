(function(e, a) { for(var i in a) e[i] = a[i]; }(exports, /******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};
/******/
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/
/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId]) {
/******/ 			return installedModules[moduleId].exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			i: moduleId,
/******/ 			l: false,
/******/ 			exports: {}
/******/ 		};
/******/
/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/
/******/ 		// Flag the module as loaded
/******/ 		module.l = true;
/******/
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/
/******/
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;
/******/
/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;
/******/
/******/ 	// define getter function for harmony exports
/******/ 	__webpack_require__.d = function(exports, name, getter) {
/******/ 		if(!__webpack_require__.o(exports, name)) {
/******/ 			Object.defineProperty(exports, name, { enumerable: true, get: getter });
/******/ 		}
/******/ 	};
/******/
/******/ 	// define __esModule on exports
/******/ 	__webpack_require__.r = function(exports) {
/******/ 		if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 			Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 		}
/******/ 		Object.defineProperty(exports, '__esModule', { value: true });
/******/ 	};
/******/
/******/ 	// create a fake namespace object
/******/ 	// mode & 1: value is a module id, require it
/******/ 	// mode & 2: merge all properties of value into the ns
/******/ 	// mode & 4: return value when already ns object
/******/ 	// mode & 8|1: behave like require
/******/ 	__webpack_require__.t = function(value, mode) {
/******/ 		if(mode & 1) value = __webpack_require__(value);
/******/ 		if(mode & 8) return value;
/******/ 		if((mode & 4) && typeof value === 'object' && value && value.__esModule) return value;
/******/ 		var ns = Object.create(null);
/******/ 		__webpack_require__.r(ns);
/******/ 		Object.defineProperty(ns, 'default', { enumerable: true, value: value });
/******/ 		if(mode & 2 && typeof value != 'string') for(var key in value) __webpack_require__.d(ns, key, function(key) { return value[key]; }.bind(null, key));
/******/ 		return ns;
/******/ 	};
/******/
/******/ 	// getDefaultExport function for compatibility with non-harmony modules
/******/ 	__webpack_require__.n = function(module) {
/******/ 		var getter = module && module.__esModule ?
/******/ 			function getDefault() { return module['default']; } :
/******/ 			function getModuleExports() { return module; };
/******/ 		__webpack_require__.d(getter, 'a', getter);
/******/ 		return getter;
/******/ 	};
/******/
/******/ 	// Object.prototype.hasOwnProperty.call
/******/ 	__webpack_require__.o = function(object, property) { return Object.prototype.hasOwnProperty.call(object, property); };
/******/
/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "";
/******/
/******/
/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(__webpack_require__.s = 0);
/******/ })
/************************************************************************/
/******/ ([
/* 0 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
Object.defineProperty(exports, "__esModule", { value: true });
exports.deactivate = exports.activate = void 0;
const vscode = __webpack_require__(1);
const github_1 = __webpack_require__(2);
const githubServer_1 = __webpack_require__(17);
const logger_1 = __webpack_require__(14);
const vscode_extension_telemetry_1 = __webpack_require__(20);
const experimentationService_1 = __webpack_require__(21);
async function activate(context) {
    const { name, version, aiKey } = __webpack_require__(64);
    const telemetryReporter = new experimentationService_1.ExperimentationTelemetry(new vscode_extension_telemetry_1.default(name, version, aiKey));
    const experimentationService = await (0, experimentationService_1.createExperimentationService)(context, telemetryReporter);
    await experimentationService.initialFetch;
    context.subscriptions.push(vscode.window.registerUriHandler(githubServer_1.uriHandler));
    const loginService = new github_1.GitHubAuthenticationProvider(context, telemetryReporter);
    await loginService.initialize(context);
    context.subscriptions.push(vscode.commands.registerCommand('github.provide-token', () => {
        return loginService.manuallyProvideToken();
    }));
    context.subscriptions.push(vscode.authentication.registerAuthenticationProvider('github', 'GitHub', {
        onDidChangeSessions: github_1.onDidChangeSessions.event,
        getSessions: (scopes) => loginService.getSessions(scopes),
        createSession: async (scopeList) => {
            try {
                /* __GDPR__
                    "login" : { }
                */
                telemetryReporter.sendTelemetryEvent('login');
                const session = await loginService.createSession(scopeList.sort().join(' '));
                logger_1.default.info('Login success!');
                github_1.onDidChangeSessions.fire({ added: [session], removed: [], changed: [] });
                return session;
            }
            catch (e) {
                // If login was cancelled, do not notify user.
                if (e.message === 'Cancelled') {
                    /* __GDPR__
                        "loginCancelled" : { }
                    */
                    telemetryReporter.sendTelemetryEvent('loginCancelled');
                    throw e;
                }
                /* __GDPR__
                    "loginFailed" : { }
                */
                telemetryReporter.sendTelemetryEvent('loginFailed');
                vscode.window.showErrorMessage(`Sign in failed: ${e}`);
                logger_1.default.error(e);
                throw e;
            }
        },
        removeSession: async (id) => {
            try {
                /* __GDPR__
                    "logout" : { }
                */
                telemetryReporter.sendTelemetryEvent('logout');
                const session = await loginService.removeSession(id);
                if (session) {
                    github_1.onDidChangeSessions.fire({ added: [], removed: [session], changed: [] });
                }
            }
            catch (e) {
                /* __GDPR__
                    "logoutFailed" : { }
                */
                telemetryReporter.sendTelemetryEvent('logoutFailed');
                vscode.window.showErrorMessage(`Sign out failed: ${e}`);
                logger_1.default.error(e);
                throw e;
            }
        }
    }, { supportsMultipleAccounts: false }));
    return;
}
exports.activate = activate;
// this method is called when your extension is deactivated
function deactivate() { }
exports.deactivate = deactivate;


/***/ }),
/* 1 */
/***/ (function(module, exports) {

module.exports = require("vscode");

/***/ }),
/* 2 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
Object.defineProperty(exports, "__esModule", { value: true });
exports.GitHubAuthenticationProvider = exports.onDidChangeSessions = void 0;
const vscode = __webpack_require__(1);
const uuid_1 = __webpack_require__(3);
const keychain_1 = __webpack_require__(13);
const githubServer_1 = __webpack_require__(17);
const logger_1 = __webpack_require__(14);
const utils_1 = __webpack_require__(19);
exports.onDidChangeSessions = new vscode.EventEmitter();
class GitHubAuthenticationProvider {
    constructor(context, telemetryReporter) {
        this._sessions = [];
        this._keychain = new keychain_1.Keychain(context);
        this._githubServer = new githubServer_1.GitHubServer(telemetryReporter);
    }
    async initialize(context) {
        try {
            this._sessions = await this.readSessions();
            await this.verifySessions();
        }
        catch (e) {
            // Ignore, network request failed
        }
        context.subscriptions.push(context.secrets.onDidChange(() => this.checkForUpdates()));
    }
    async getSessions(scopes) {
        return scopes
            ? this._sessions.filter(session => (0, utils_1.arrayEquals)(session.scopes, scopes))
            : this._sessions;
    }
    async verifySessions() {
        const verifiedSessions = [];
        const verificationPromises = this._sessions.map(async (session) => {
            try {
                await this._githubServer.getUserInfo(session.accessToken);
                this._githubServer.checkIsEdu(session.accessToken);
                verifiedSessions.push(session);
            }
            catch (e) {
                // Remove sessions that return unauthorized response
                if (e.message !== 'Unauthorized') {
                    verifiedSessions.push(session);
                }
            }
        });
        Promise.all(verificationPromises).then(_ => {
            if (this._sessions.length !== verifiedSessions.length) {
                this._sessions = verifiedSessions;
                this.storeSessions();
            }
        });
    }
    async checkForUpdates() {
        let storedSessions;
        try {
            storedSessions = await this.readSessions();
        }
        catch (e) {
            // Ignore, network request failed
            return;
        }
        const added = [];
        const removed = [];
        storedSessions.forEach(session => {
            const matchesExisting = this._sessions.some(s => s.id === session.id);
            // Another window added a session to the keychain, add it to our state as well
            if (!matchesExisting) {
                logger_1.default.info('Adding session found in keychain');
                this._sessions.push(session);
                added.push(session);
            }
        });
        this._sessions.map(session => {
            const matchesExisting = storedSessions.some(s => s.id === session.id);
            // Another window has logged out, remove from our state
            if (!matchesExisting) {
                logger_1.default.info('Removing session no longer found in keychain');
                const sessionIndex = this._sessions.findIndex(s => s.id === session.id);
                if (sessionIndex > -1) {
                    this._sessions.splice(sessionIndex, 1);
                }
                removed.push(session);
            }
        });
        if (added.length || removed.length) {
            exports.onDidChangeSessions.fire({ added, removed, changed: [] });
        }
    }
    async readSessions() {
        const storedSessions = await this._keychain.getToken() || await this._keychain.tryMigrate();
        if (storedSessions) {
            try {
                const sessionData = JSON.parse(storedSessions);
                const sessionPromises = sessionData.map(async (session) => {
                    var _a, _b;
                    const needsUserInfo = !session.account;
                    let userInfo;
                    if (needsUserInfo) {
                        userInfo = await this._githubServer.getUserInfo(session.accessToken);
                    }
                    return {
                        id: session.id,
                        account: {
                            label: session.account
                                ? session.account.label || session.account.displayName
                                : userInfo.accountName,
                            id: (_b = (_a = session.account) === null || _a === void 0 ? void 0 : _a.id) !== null && _b !== void 0 ? _b : userInfo.id
                        },
                        scopes: session.scopes,
                        accessToken: session.accessToken
                    };
                });
                return Promise.all(sessionPromises);
            }
            catch (e) {
                if (e === githubServer_1.NETWORK_ERROR) {
                    return [];
                }
                logger_1.default.error(`Error reading sessions: ${e}`);
                await this._keychain.deleteToken();
            }
        }
        return [];
    }
    async storeSessions() {
        await this._keychain.setToken(JSON.stringify(this._sessions));
    }
    get sessions() {
        return this._sessions;
    }
    async createSession(scopes) {
        const token = await this._githubServer.login(scopes);
        const session = await this.tokenToSession(token, scopes.split(' '));
        this._githubServer.checkIsEdu(token);
        await this.setToken(session);
        return session;
    }
    async manuallyProvideToken() {
        this._githubServer.manuallyProvideToken();
    }
    async tokenToSession(token, scopes) {
        const userInfo = await this._githubServer.getUserInfo(token);
        return {
            id: (0, uuid_1.v4)(),
            accessToken: token,
            account: { label: userInfo.accountName, id: userInfo.id },
            scopes
        };
    }
    async setToken(session) {
        const sessionIndex = this._sessions.findIndex(s => s.id === session.id);
        if (sessionIndex > -1) {
            this._sessions.splice(sessionIndex, 1, session);
        }
        else {
            this._sessions.push(session);
        }
        await this.storeSessions();
    }
    async removeSession(id) {
        logger_1.default.info(`Logging out of ${id}`);
        const sessionIndex = this._sessions.findIndex(session => session.id === id);
        let session;
        if (sessionIndex > -1) {
            session = this._sessions[sessionIndex];
            this._sessions.splice(sessionIndex, 1);
        }
        else {
            logger_1.default.error('Session not found');
        }
        await this.storeSessions();
        return session;
    }
}
exports.GitHubAuthenticationProvider = GitHubAuthenticationProvider;


/***/ }),
/* 3 */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _v1_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(4);
/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "v1", function() { return _v1_js__WEBPACK_IMPORTED_MODULE_0__["default"]; });

/* harmony import */ var _v3_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(7);
/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "v3", function() { return _v3_js__WEBPACK_IMPORTED_MODULE_1__["default"]; });

/* harmony import */ var _v4_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(10);
/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "v4", function() { return _v4_js__WEBPACK_IMPORTED_MODULE_2__["default"]; });

/* harmony import */ var _v5_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(11);
/* harmony reexport (safe) */ __webpack_require__.d(__webpack_exports__, "v5", function() { return _v5_js__WEBPACK_IMPORTED_MODULE_3__["default"]; });






/***/ }),
/* 4 */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _rng_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(5);
/* harmony import */ var _bytesToUuid_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(6);

 // **`v1()` - Generate time-based UUID**
//
// Inspired by https://github.com/LiosK/UUID.js
// and http://docs.python.org/library/uuid.html

var _nodeId;

var _clockseq; // Previous uuid creation time


var _lastMSecs = 0;
var _lastNSecs = 0; // See https://github.com/uuidjs/uuid for API details

function v1(options, buf, offset) {
  var i = buf && offset || 0;
  var b = buf || [];
  options = options || {};
  var node = options.node || _nodeId;
  var clockseq = options.clockseq !== undefined ? options.clockseq : _clockseq; // node and clockseq need to be initialized to random values if they're not
  // specified.  We do this lazily to minimize issues related to insufficient
  // system entropy.  See #189

  if (node == null || clockseq == null) {
    var seedBytes = options.random || (options.rng || _rng_js__WEBPACK_IMPORTED_MODULE_0__["default"])();

    if (node == null) {
      // Per 4.5, create and 48-bit node id, (47 random bits + multicast bit = 1)
      node = _nodeId = [seedBytes[0] | 0x01, seedBytes[1], seedBytes[2], seedBytes[3], seedBytes[4], seedBytes[5]];
    }

    if (clockseq == null) {
      // Per 4.2.2, randomize (14 bit) clockseq
      clockseq = _clockseq = (seedBytes[6] << 8 | seedBytes[7]) & 0x3fff;
    }
  } // UUID timestamps are 100 nano-second units since the Gregorian epoch,
  // (1582-10-15 00:00).  JSNumbers aren't precise enough for this, so
  // time is handled internally as 'msecs' (integer milliseconds) and 'nsecs'
  // (100-nanoseconds offset from msecs) since unix epoch, 1970-01-01 00:00.


  var msecs = options.msecs !== undefined ? options.msecs : Date.now(); // Per 4.2.1.2, use count of uuid's generated during the current clock
  // cycle to simulate higher resolution clock

  var nsecs = options.nsecs !== undefined ? options.nsecs : _lastNSecs + 1; // Time since last uuid creation (in msecs)

  var dt = msecs - _lastMSecs + (nsecs - _lastNSecs) / 10000; // Per 4.2.1.2, Bump clockseq on clock regression

  if (dt < 0 && options.clockseq === undefined) {
    clockseq = clockseq + 1 & 0x3fff;
  } // Reset nsecs if clock regresses (new clockseq) or we've moved onto a new
  // time interval


  if ((dt < 0 || msecs > _lastMSecs) && options.nsecs === undefined) {
    nsecs = 0;
  } // Per 4.2.1.2 Throw error if too many uuids are requested


  if (nsecs >= 10000) {
    throw new Error("uuid.v1(): Can't create more than 10M uuids/sec");
  }

  _lastMSecs = msecs;
  _lastNSecs = nsecs;
  _clockseq = clockseq; // Per 4.1.4 - Convert from unix epoch to Gregorian epoch

  msecs += 12219292800000; // `time_low`

  var tl = ((msecs & 0xfffffff) * 10000 + nsecs) % 0x100000000;
  b[i++] = tl >>> 24 & 0xff;
  b[i++] = tl >>> 16 & 0xff;
  b[i++] = tl >>> 8 & 0xff;
  b[i++] = tl & 0xff; // `time_mid`

  var tmh = msecs / 0x100000000 * 10000 & 0xfffffff;
  b[i++] = tmh >>> 8 & 0xff;
  b[i++] = tmh & 0xff; // `time_high_and_version`

  b[i++] = tmh >>> 24 & 0xf | 0x10; // include version

  b[i++] = tmh >>> 16 & 0xff; // `clock_seq_hi_and_reserved` (Per 4.2.2 - include variant)

  b[i++] = clockseq >>> 8 | 0x80; // `clock_seq_low`

  b[i++] = clockseq & 0xff; // `node`

  for (var n = 0; n < 6; ++n) {
    b[i + n] = node[n];
  }

  return buf || Object(_bytesToUuid_js__WEBPACK_IMPORTED_MODULE_1__["default"])(b);
}

/* harmony default export */ __webpack_exports__["default"] = (v1);

/***/ }),
/* 5 */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "default", function() { return rng; });
// Unique ID creation requires a high quality random # generator. In the browser we therefore
// require the crypto API and do not support built-in fallback to lower quality random number
// generators (like Math.random()).
// getRandomValues needs to be invoked in a context where "this" is a Crypto implementation. Also,
// find the complete implementation of crypto (msCrypto) on IE11.
var getRandomValues = typeof crypto !== 'undefined' && crypto.getRandomValues && crypto.getRandomValues.bind(crypto) || typeof msCrypto !== 'undefined' && typeof msCrypto.getRandomValues === 'function' && msCrypto.getRandomValues.bind(msCrypto);
var rnds8 = new Uint8Array(16);
function rng() {
  if (!getRandomValues) {
    throw new Error('crypto.getRandomValues() not supported. See https://github.com/uuidjs/uuid#getrandomvalues-not-supported');
  }

  return getRandomValues(rnds8);
}

/***/ }),
/* 6 */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/**
 * Convert array of 16 byte values to UUID string format of the form:
 * XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
 */
var byteToHex = [];

for (var i = 0; i < 256; ++i) {
  byteToHex.push((i + 0x100).toString(16).substr(1));
}

function bytesToUuid(buf, offset) {
  var i = offset || 0;
  var bth = byteToHex; // Note: Be careful editing this code!  It's been tuned for performance
  // and works in ways you may not expect. See https://github.com/uuidjs/uuid/pull/434

  return (bth[buf[i + 0]] + bth[buf[i + 1]] + bth[buf[i + 2]] + bth[buf[i + 3]] + '-' + bth[buf[i + 4]] + bth[buf[i + 5]] + '-' + bth[buf[i + 6]] + bth[buf[i + 7]] + '-' + bth[buf[i + 8]] + bth[buf[i + 9]] + '-' + bth[buf[i + 10]] + bth[buf[i + 11]] + bth[buf[i + 12]] + bth[buf[i + 13]] + bth[buf[i + 14]] + bth[buf[i + 15]]).toLowerCase();
}

/* harmony default export */ __webpack_exports__["default"] = (bytesToUuid);

/***/ }),
/* 7 */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _v35_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(8);
/* harmony import */ var _md5_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(9);


var v3 = Object(_v35_js__WEBPACK_IMPORTED_MODULE_0__["default"])('v3', 0x30, _md5_js__WEBPACK_IMPORTED_MODULE_1__["default"]);
/* harmony default export */ __webpack_exports__["default"] = (v3);

/***/ }),
/* 8 */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "DNS", function() { return DNS; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "URL", function() { return URL; });
/* harmony import */ var _bytesToUuid_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(6);


function uuidToBytes(uuid) {
  // Note: We assume we're being passed a valid uuid string
  var bytes = [];
  uuid.replace(/[a-fA-F0-9]{2}/g, function (hex) {
    bytes.push(parseInt(hex, 16));
  });
  return bytes;
}

function stringToBytes(str) {
  str = unescape(encodeURIComponent(str)); // UTF8 escape

  var bytes = [];

  for (var i = 0; i < str.length; ++i) {
    bytes.push(str.charCodeAt(i));
  }

  return bytes;
}

var DNS = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
var URL = '6ba7b811-9dad-11d1-80b4-00c04fd430c8';
/* harmony default export */ __webpack_exports__["default"] = (function (name, version, hashfunc) {
  function generateUUID(value, namespace, buf, offset) {
    var off = buf && offset || 0;
    if (typeof value === 'string') value = stringToBytes(value);
    if (typeof namespace === 'string') namespace = uuidToBytes(namespace);

    if (!Array.isArray(value)) {
      throw TypeError('value must be an array of bytes');
    }

    if (!Array.isArray(namespace) || namespace.length !== 16) {
      throw TypeError('namespace must be uuid string or an Array of 16 byte values');
    } // Per 4.3


    var bytes = hashfunc(namespace.concat(value));
    bytes[6] = bytes[6] & 0x0f | version;
    bytes[8] = bytes[8] & 0x3f | 0x80;

    if (buf) {
      for (var idx = 0; idx < 16; ++idx) {
        buf[off + idx] = bytes[idx];
      }
    }

    return buf || Object(_bytesToUuid_js__WEBPACK_IMPORTED_MODULE_0__["default"])(bytes);
  } // Function#name is not settable on some platforms (#270)


  try {
    generateUUID.name = name; // eslint-disable-next-line no-empty
  } catch (err) {} // For CommonJS default export support


  generateUUID.DNS = DNS;
  generateUUID.URL = URL;
  return generateUUID;
});

/***/ }),
/* 9 */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/*
 * Browser-compatible JavaScript MD5
 *
 * Modification of JavaScript MD5
 * https://github.com/blueimp/JavaScript-MD5
 *
 * Copyright 2011, Sebastian Tschan
 * https://blueimp.net
 *
 * Licensed under the MIT license:
 * https://opensource.org/licenses/MIT
 *
 * Based on
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Version 2.2 Copyright (C) Paul Johnston 1999 - 2009
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for more info.
 */
function md5(bytes) {
  if (typeof bytes === 'string') {
    var msg = unescape(encodeURIComponent(bytes)); // UTF8 escape

    bytes = new Uint8Array(msg.length);

    for (var i = 0; i < msg.length; ++i) {
      bytes[i] = msg.charCodeAt(i);
    }
  }

  return md5ToHexEncodedArray(wordsToMd5(bytesToWords(bytes), bytes.length * 8));
}
/*
 * Convert an array of little-endian words to an array of bytes
 */


function md5ToHexEncodedArray(input) {
  var output = [];
  var length32 = input.length * 32;
  var hexTab = '0123456789abcdef';

  for (var i = 0; i < length32; i += 8) {
    var x = input[i >> 5] >>> i % 32 & 0xff;
    var hex = parseInt(hexTab.charAt(x >>> 4 & 0x0f) + hexTab.charAt(x & 0x0f), 16);
    output.push(hex);
  }

  return output;
}
/**
 * Calculate output length with padding and bit length
 */


function getOutputLength(inputLength8) {
  return (inputLength8 + 64 >>> 9 << 4) + 14 + 1;
}
/*
 * Calculate the MD5 of an array of little-endian words, and a bit length.
 */


function wordsToMd5(x, len) {
  /* append padding */
  x[len >> 5] |= 0x80 << len % 32;
  x[getOutputLength(len) - 1] = len;
  var a = 1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d = 271733878;

  for (var i = 0; i < x.length; i += 16) {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;
    a = md5ff(a, b, c, d, x[i], 7, -680876936);
    d = md5ff(d, a, b, c, x[i + 1], 12, -389564586);
    c = md5ff(c, d, a, b, x[i + 2], 17, 606105819);
    b = md5ff(b, c, d, a, x[i + 3], 22, -1044525330);
    a = md5ff(a, b, c, d, x[i + 4], 7, -176418897);
    d = md5ff(d, a, b, c, x[i + 5], 12, 1200080426);
    c = md5ff(c, d, a, b, x[i + 6], 17, -1473231341);
    b = md5ff(b, c, d, a, x[i + 7], 22, -45705983);
    a = md5ff(a, b, c, d, x[i + 8], 7, 1770035416);
    d = md5ff(d, a, b, c, x[i + 9], 12, -1958414417);
    c = md5ff(c, d, a, b, x[i + 10], 17, -42063);
    b = md5ff(b, c, d, a, x[i + 11], 22, -1990404162);
    a = md5ff(a, b, c, d, x[i + 12], 7, 1804603682);
    d = md5ff(d, a, b, c, x[i + 13], 12, -40341101);
    c = md5ff(c, d, a, b, x[i + 14], 17, -1502002290);
    b = md5ff(b, c, d, a, x[i + 15], 22, 1236535329);
    a = md5gg(a, b, c, d, x[i + 1], 5, -165796510);
    d = md5gg(d, a, b, c, x[i + 6], 9, -1069501632);
    c = md5gg(c, d, a, b, x[i + 11], 14, 643717713);
    b = md5gg(b, c, d, a, x[i], 20, -373897302);
    a = md5gg(a, b, c, d, x[i + 5], 5, -701558691);
    d = md5gg(d, a, b, c, x[i + 10], 9, 38016083);
    c = md5gg(c, d, a, b, x[i + 15], 14, -660478335);
    b = md5gg(b, c, d, a, x[i + 4], 20, -405537848);
    a = md5gg(a, b, c, d, x[i + 9], 5, 568446438);
    d = md5gg(d, a, b, c, x[i + 14], 9, -1019803690);
    c = md5gg(c, d, a, b, x[i + 3], 14, -187363961);
    b = md5gg(b, c, d, a, x[i + 8], 20, 1163531501);
    a = md5gg(a, b, c, d, x[i + 13], 5, -1444681467);
    d = md5gg(d, a, b, c, x[i + 2], 9, -51403784);
    c = md5gg(c, d, a, b, x[i + 7], 14, 1735328473);
    b = md5gg(b, c, d, a, x[i + 12], 20, -1926607734);
    a = md5hh(a, b, c, d, x[i + 5], 4, -378558);
    d = md5hh(d, a, b, c, x[i + 8], 11, -2022574463);
    c = md5hh(c, d, a, b, x[i + 11], 16, 1839030562);
    b = md5hh(b, c, d, a, x[i + 14], 23, -35309556);
    a = md5hh(a, b, c, d, x[i + 1], 4, -1530992060);
    d = md5hh(d, a, b, c, x[i + 4], 11, 1272893353);
    c = md5hh(c, d, a, b, x[i + 7], 16, -155497632);
    b = md5hh(b, c, d, a, x[i + 10], 23, -1094730640);
    a = md5hh(a, b, c, d, x[i + 13], 4, 681279174);
    d = md5hh(d, a, b, c, x[i], 11, -358537222);
    c = md5hh(c, d, a, b, x[i + 3], 16, -722521979);
    b = md5hh(b, c, d, a, x[i + 6], 23, 76029189);
    a = md5hh(a, b, c, d, x[i + 9], 4, -640364487);
    d = md5hh(d, a, b, c, x[i + 12], 11, -421815835);
    c = md5hh(c, d, a, b, x[i + 15], 16, 530742520);
    b = md5hh(b, c, d, a, x[i + 2], 23, -995338651);
    a = md5ii(a, b, c, d, x[i], 6, -198630844);
    d = md5ii(d, a, b, c, x[i + 7], 10, 1126891415);
    c = md5ii(c, d, a, b, x[i + 14], 15, -1416354905);
    b = md5ii(b, c, d, a, x[i + 5], 21, -57434055);
    a = md5ii(a, b, c, d, x[i + 12], 6, 1700485571);
    d = md5ii(d, a, b, c, x[i + 3], 10, -1894986606);
    c = md5ii(c, d, a, b, x[i + 10], 15, -1051523);
    b = md5ii(b, c, d, a, x[i + 1], 21, -2054922799);
    a = md5ii(a, b, c, d, x[i + 8], 6, 1873313359);
    d = md5ii(d, a, b, c, x[i + 15], 10, -30611744);
    c = md5ii(c, d, a, b, x[i + 6], 15, -1560198380);
    b = md5ii(b, c, d, a, x[i + 13], 21, 1309151649);
    a = md5ii(a, b, c, d, x[i + 4], 6, -145523070);
    d = md5ii(d, a, b, c, x[i + 11], 10, -1120210379);
    c = md5ii(c, d, a, b, x[i + 2], 15, 718787259);
    b = md5ii(b, c, d, a, x[i + 9], 21, -343485551);
    a = safeAdd(a, olda);
    b = safeAdd(b, oldb);
    c = safeAdd(c, oldc);
    d = safeAdd(d, oldd);
  }

  return [a, b, c, d];
}
/*
 * Convert an array bytes to an array of little-endian words
 * Characters >255 have their high-byte silently ignored.
 */


function bytesToWords(input) {
  if (input.length === 0) {
    return [];
  }

  var length8 = input.length * 8;
  var output = new Uint32Array(getOutputLength(length8));

  for (var i = 0; i < length8; i += 8) {
    output[i >> 5] |= (input[i / 8] & 0xff) << i % 32;
  }

  return output;
}
/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */


function safeAdd(x, y) {
  var lsw = (x & 0xffff) + (y & 0xffff);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return msw << 16 | lsw & 0xffff;
}
/*
 * Bitwise rotate a 32-bit number to the left.
 */


function bitRotateLeft(num, cnt) {
  return num << cnt | num >>> 32 - cnt;
}
/*
 * These functions implement the four basic operations the algorithm uses.
 */


function md5cmn(q, a, b, x, s, t) {
  return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
}

function md5ff(a, b, c, d, x, s, t) {
  return md5cmn(b & c | ~b & d, a, b, x, s, t);
}

function md5gg(a, b, c, d, x, s, t) {
  return md5cmn(b & d | c & ~d, a, b, x, s, t);
}

function md5hh(a, b, c, d, x, s, t) {
  return md5cmn(b ^ c ^ d, a, b, x, s, t);
}

function md5ii(a, b, c, d, x, s, t) {
  return md5cmn(c ^ (b | ~d), a, b, x, s, t);
}

/* harmony default export */ __webpack_exports__["default"] = (md5);

/***/ }),
/* 10 */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _rng_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(5);
/* harmony import */ var _bytesToUuid_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(6);



function v4(options, buf, offset) {
  if (typeof options === 'string') {
    buf = options === 'binary' ? new Uint8Array(16) : null;
    options = null;
  }

  options = options || {};
  var rnds = options.random || (options.rng || _rng_js__WEBPACK_IMPORTED_MODULE_0__["default"])(); // Per 4.4, set bits for version and `clock_seq_hi_and_reserved`

  rnds[6] = rnds[6] & 0x0f | 0x40;
  rnds[8] = rnds[8] & 0x3f | 0x80; // Copy bytes to buffer, if provided

  if (buf) {
    var start = offset || 0;

    for (var i = 0; i < 16; ++i) {
      buf[start + i] = rnds[i];
    }

    return buf;
  }

  return Object(_bytesToUuid_js__WEBPACK_IMPORTED_MODULE_1__["default"])(rnds);
}

/* harmony default export */ __webpack_exports__["default"] = (v4);

/***/ }),
/* 11 */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony import */ var _v35_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(8);
/* harmony import */ var _sha1_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(12);


var v5 = Object(_v35_js__WEBPACK_IMPORTED_MODULE_0__["default"])('v5', 0x50, _sha1_js__WEBPACK_IMPORTED_MODULE_1__["default"]);
/* harmony default export */ __webpack_exports__["default"] = (v5);

/***/ }),
/* 12 */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
// Adapted from Chris Veness' SHA1 code at
// http://www.movable-type.co.uk/scripts/sha1.html
function f(s, x, y, z) {
  switch (s) {
    case 0:
      return x & y ^ ~x & z;

    case 1:
      return x ^ y ^ z;

    case 2:
      return x & y ^ x & z ^ y & z;

    case 3:
      return x ^ y ^ z;
  }
}

function ROTL(x, n) {
  return x << n | x >>> 32 - n;
}

function sha1(bytes) {
  var K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];
  var H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

  if (typeof bytes === 'string') {
    var msg = unescape(encodeURIComponent(bytes)); // UTF8 escape

    bytes = [];

    for (var i = 0; i < msg.length; ++i) {
      bytes.push(msg.charCodeAt(i));
    }
  }

  bytes.push(0x80);
  var l = bytes.length / 4 + 2;
  var N = Math.ceil(l / 16);
  var M = new Array(N);

  for (var _i = 0; _i < N; ++_i) {
    var arr = new Uint32Array(16);

    for (var j = 0; j < 16; ++j) {
      arr[j] = bytes[_i * 64 + j * 4] << 24 | bytes[_i * 64 + j * 4 + 1] << 16 | bytes[_i * 64 + j * 4 + 2] << 8 | bytes[_i * 64 + j * 4 + 3];
    }

    M[_i] = arr;
  }

  M[N - 1][14] = (bytes.length - 1) * 8 / Math.pow(2, 32);
  M[N - 1][14] = Math.floor(M[N - 1][14]);
  M[N - 1][15] = (bytes.length - 1) * 8 & 0xffffffff;

  for (var _i2 = 0; _i2 < N; ++_i2) {
    var W = new Uint32Array(80);

    for (var t = 0; t < 16; ++t) {
      W[t] = M[_i2][t];
    }

    for (var _t = 16; _t < 80; ++_t) {
      W[_t] = ROTL(W[_t - 3] ^ W[_t - 8] ^ W[_t - 14] ^ W[_t - 16], 1);
    }

    var a = H[0];
    var b = H[1];
    var c = H[2];
    var d = H[3];
    var e = H[4];

    for (var _t2 = 0; _t2 < 80; ++_t2) {
      var s = Math.floor(_t2 / 20);
      var T = ROTL(a, 5) + f(s, b, c, d) + e + K[s] + W[_t2] >>> 0;
      e = d;
      d = c;
      c = ROTL(b, 30) >>> 0;
      b = a;
      a = T;
    }

    H[0] = H[0] + a >>> 0;
    H[1] = H[1] + b >>> 0;
    H[2] = H[2] + c >>> 0;
    H[3] = H[3] + d >>> 0;
    H[4] = H[4] + e >>> 0;
  }

  return [H[0] >> 24 & 0xff, H[0] >> 16 & 0xff, H[0] >> 8 & 0xff, H[0] & 0xff, H[1] >> 24 & 0xff, H[1] >> 16 & 0xff, H[1] >> 8 & 0xff, H[1] & 0xff, H[2] >> 24 & 0xff, H[2] >> 16 & 0xff, H[2] >> 8 & 0xff, H[2] & 0xff, H[3] >> 24 & 0xff, H[3] >> 16 & 0xff, H[3] >> 8 & 0xff, H[3] & 0xff, H[4] >> 24 & 0xff, H[4] >> 16 & 0xff, H[4] >> 8 & 0xff, H[4] & 0xff];
}

/* harmony default export */ __webpack_exports__["default"] = (sha1);

/***/ }),
/* 13 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
Object.defineProperty(exports, "__esModule", { value: true });
exports.Keychain = void 0;
const vscode = __webpack_require__(1);
const logger_1 = __webpack_require__(14);
const nls = __webpack_require__(15);
const localize = nls.loadMessageBundle();
function getKeytar() {
    try {
        return __webpack_require__(16);
    }
    catch (err) {
        console.log(err);
    }
    return undefined;
}
const SERVICE_ID = `github.auth`;
class Keychain {
    constructor(context) {
        this.context = context;
    }
    async setToken(token) {
        try {
            return await this.context.secrets.store(SERVICE_ID, token);
        }
        catch (e) {
            // Ignore
            logger_1.default.error(`Setting token failed: ${e}`);
            const troubleshooting = localize('troubleshooting', "Troubleshooting Guide");
            const result = await vscode.window.showErrorMessage(localize('keychainWriteError', "Writing login information to the keychain failed with error '{0}'.", e.message), troubleshooting);
            if (result === troubleshooting) {
                vscode.env.openExternal(vscode.Uri.parse('https://code.visualstudio.com/docs/editor/settings-sync#_troubleshooting-keychain-issues'));
            }
        }
    }
    async getToken() {
        try {
            return await this.context.secrets.get(SERVICE_ID);
        }
        catch (e) {
            // Ignore
            logger_1.default.error(`Getting token failed: ${e}`);
            return Promise.resolve(undefined);
        }
    }
    async deleteToken() {
        try {
            return await this.context.secrets.delete(SERVICE_ID);
        }
        catch (e) {
            // Ignore
            logger_1.default.error(`Deleting token failed: ${e}`);
            return Promise.resolve(undefined);
        }
    }
    async tryMigrate() {
        try {
            const keytar = getKeytar();
            if (!keytar) {
                throw new Error('keytar unavailable');
            }
            const oldValue = await keytar.getPassword(`${vscode.env.uriScheme}-github.login`, 'account');
            if (oldValue) {
                await this.setToken(oldValue);
                await keytar.deletePassword(`${vscode.env.uriScheme}-github.login`, 'account');
            }
            return oldValue;
        }
        catch (_) {
            // Ignore
            return Promise.resolve(undefined);
        }
    }
}
exports.Keychain = Keychain;


/***/ }),
/* 14 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
Object.defineProperty(exports, "__esModule", { value: true });
const vscode = __webpack_require__(1);
class Log {
    constructor() {
        this.output = vscode.window.createOutputChannel('GitHub Authentication');
    }
    data2String(data) {
        if (data instanceof Error) {
            return data.stack || data.message;
        }
        if (data.success === false && data.message) {
            return data.message;
        }
        return data.toString();
    }
    info(message, data) {
        this.logLevel('Info', message, data);
    }
    error(message, data) {
        this.logLevel('Error', message, data);
    }
    logLevel(level, message, data) {
        this.output.appendLine(`[${level}  - ${this.now()}] ${message}`);
        if (data) {
            this.output.appendLine(this.data2String(data));
        }
    }
    now() {
        const now = new Date();
        return padLeft(now.getUTCHours() + '', 2, '0')
            + ':' + padLeft(now.getMinutes() + '', 2, '0')
            + ':' + padLeft(now.getUTCSeconds() + '', 2, '0') + '.' + now.getMilliseconds();
    }
}
function padLeft(s, n, pad = ' ') {
    return pad.repeat(Math.max(0, n - s.length)) + s;
}
const Logger = new Log();
exports.default = Logger;


/***/ }),
/* 15 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/


Object.defineProperty(exports, "__esModule", { value: true });

function format(message, args) {
	let result;
	// if (isPseudo) {
	// 	// FF3B and FF3D is the Unicode zenkaku representation for [ and ]
	// 	message = '\uFF3B' + message.replace(/[aouei]/g, '$&$&') + '\uFF3D';
	// }
	if (args.length === 0) {
		result = message;
	}
	else {
		result = message.replace(/\{(\d+)\}/g, function (match, rest) {
			let index = rest[0];
			let arg = args[index];
			let replacement = match;
			if (typeof arg === 'string') {
				replacement = arg;
			}
			else if (typeof arg === 'number' || typeof arg === 'boolean' || arg === void 0 || arg === null) {
				replacement = String(arg);
			}
			return replacement;
		});
	}
	return result;
}

function localize(key, message) {
	let args = [];
	for (let _i = 2; _i < arguments.length; _i++) {
		args[_i - 2] = arguments[_i];
	}
	return format(message, args);
}

function loadMessageBundle(file) {
	return localize;
}

let MessageFormat;
(function (MessageFormat) {
	MessageFormat["file"] = "file";
	MessageFormat["bundle"] = "bundle";
	MessageFormat["both"] = "both";
})(MessageFormat = exports.MessageFormat || (exports.MessageFormat = {}));
let BundleFormat;
(function (BundleFormat) {
	// the nls.bundle format
	BundleFormat["standalone"] = "standalone";
	BundleFormat["languagePack"] = "languagePack";
})(BundleFormat = exports.BundleFormat || (exports.BundleFormat = {}));

exports.loadMessageBundle = loadMessageBundle;
function config(opts) {
	if (opts) {
		if (isString(opts.locale)) {
			options.locale = opts.locale.toLowerCase();
			options.language = options.locale;
			resolvedLanguage = undefined;
			resolvedBundles = Object.create(null);
		}
		if (opts.messageFormat !== undefined) {
			options.messageFormat = opts.messageFormat;
		}
		if (opts.bundleFormat === BundleFormat.standalone && options.languagePackSupport === true) {
			options.languagePackSupport = false;
		}
	}
	isPseudo = options.locale === 'pseudo';
	return loadMessageBundle;
}
exports.config = config;


/***/ }),
/* 16 */
/***/ (function(module, exports) {

module.exports = require("keytar");

/***/ }),
/* 17 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
Object.defineProperty(exports, "__esModule", { value: true });
exports.GitHubServer = exports.uriHandler = exports.NETWORK_ERROR = void 0;
const nls = __webpack_require__(15);
const vscode = __webpack_require__(1);
const node_fetch_1 = __webpack_require__(18);
const uuid_1 = __webpack_require__(3);
const utils_1 = __webpack_require__(19);
const logger_1 = __webpack_require__(14);
const localize = nls.loadMessageBundle();
exports.NETWORK_ERROR = 'network error';
const AUTH_RELAY_SERVER = 'vscode-auth.github.com';
// const AUTH_RELAY_STAGING_SERVER = 'client-auth-staging-14a768b.herokuapp.com';
class UriEventHandler extends vscode.EventEmitter {
    handleUri(uri) {
        this.fire(uri);
    }
}
exports.uriHandler = new UriEventHandler;
const onDidManuallyProvideToken = new vscode.EventEmitter();
function parseQuery(uri) {
    return uri.query.split('&').reduce((prev, current) => {
        const queryString = current.split('=');
        prev[queryString[0]] = queryString[1];
        return prev;
    }, {});
}
class GitHubServer {
    constructor(telemetryReporter) {
        this.telemetryReporter = telemetryReporter;
        this._pendingStates = new Map();
        this._codeExchangePromises = new Map();
        this.exchangeCodeForToken = (scopes) => async (uri, resolve, reject) => {
            logger_1.default.info('Exchanging code for token...');
            const query = parseQuery(uri);
            const code = query.code;
            const acceptedStates = this._pendingStates.get(scopes) || [];
            if (!acceptedStates.includes(query.state)) {
                reject('Received mismatched state');
                return;
            }
            const url = `https://${AUTH_RELAY_SERVER}/token?code=${code}&state=${query.state}`;
            // TODO@joao: remove
            if (query.nocors) {
                try {
                    const json = await vscode.commands.executeCommand('_workbench.fetchJSON', url, 'POST');
                    logger_1.default.info('Token exchange success!');
                    resolve(json.access_token);
                }
                catch (err) {
                    reject(err);
                }
            }
            else {
                try {
                    const result = await (0, node_fetch_1.default)(url, {
                        method: 'POST',
                        headers: {
                            Accept: 'application/json'
                        }
                    });
                    if (result.ok) {
                        const json = await result.json();
                        logger_1.default.info('Token exchange success!');
                        resolve(json.access_token);
                    }
                    else {
                        reject(result.statusText);
                    }
                }
                catch (ex) {
                    reject(ex);
                }
            }
        };
    }
    isTestEnvironment(url) {
        return /\.azurewebsites\.net$/.test(url.authority) || url.authority.startsWith('localhost:');
    }
    // TODO@joaomoreno TODO@RMacfarlane
    async isNoCorsEnvironment() {
        const uri = await vscode.env.asExternalUri(vscode.Uri.parse(`${vscode.env.uriScheme}://vscode.github-authentication/did-authenticate`));
        return uri.scheme === 'https' && /^vscode\./.test(uri.authority);
    }
    async login(scopes) {
        logger_1.default.info('Logging in...');
        this.updateStatusBarItem(true);
        const state = (0, uuid_1.v4)();
        // TODO@joaomoreno TODO@RMacfarlane
        const nocors = await this.isNoCorsEnvironment();
        const callbackUri = await vscode.env.asExternalUri(vscode.Uri.parse(`${vscode.env.uriScheme}://vscode.github-authentication/did-authenticate${nocors ? '?nocors=true' : ''}`));
        if (this.isTestEnvironment(callbackUri)) {
            const token = await vscode.window.showInputBox({ prompt: 'GitHub Personal Access Token', ignoreFocusOut: true });
            if (!token) {
                throw new Error('Sign in failed: No token provided');
            }
            const tokenScopes = await this.getScopes(token); // Example: ['repo', 'user']
            const scopesList = scopes.split(' '); // Example: 'read:user repo user:email'
            if (!scopesList.every(scope => {
                const included = tokenScopes.includes(scope);
                if (included || !scope.includes(':')) {
                    return included;
                }
                return scope.split(':').some(splitScopes => {
                    return tokenScopes.includes(splitScopes);
                });
            })) {
                throw new Error(`The provided token is does not match the requested scopes: ${scopes}`);
            }
            this.updateStatusBarItem(false);
            return token;
        }
        else {
            const existingStates = this._pendingStates.get(scopes) || [];
            this._pendingStates.set(scopes, [...existingStates, state]);
            const uri = vscode.Uri.parse(`https://${AUTH_RELAY_SERVER}/authorize/?callbackUri=${encodeURIComponent(callbackUri.toString())}&scope=${scopes}&state=${state}&responseType=code&authServer=https://github.com${nocors ? '&nocors=true' : ''}`);
            await vscode.env.openExternal(uri);
        }
        // Register a single listener for the URI callback, in case the user starts the login process multiple times
        // before completing it.
        let codeExchangePromise = this._codeExchangePromises.get(scopes);
        if (!codeExchangePromise) {
            codeExchangePromise = (0, utils_1.promiseFromEvent)(exports.uriHandler.event, this.exchangeCodeForToken(scopes));
            this._codeExchangePromises.set(scopes, codeExchangePromise);
        }
        return Promise.race([
            codeExchangePromise.promise,
            (0, utils_1.promiseFromEvent)(onDidManuallyProvideToken.event, (token, resolve, reject) => {
                if (!token) {
                    reject('Cancelled');
                }
                else {
                    resolve(token);
                }
            }).promise
        ]).finally(() => {
            this._pendingStates.delete(scopes);
            codeExchangePromise === null || codeExchangePromise === void 0 ? void 0 : codeExchangePromise.cancel.fire();
            this._codeExchangePromises.delete(scopes);
            this.updateStatusBarItem(false);
        });
    }
    updateStatusBarItem(isStart) {
        if (isStart && !this._statusBarItem) {
            this._statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left);
            this._statusBarItem.text = localize('signingIn', "$(mark-github) Signing in to github.com...");
            this._statusBarItem.command = 'github.provide-token';
            this._statusBarItem.show();
        }
        if (!isStart && this._statusBarItem) {
            this._statusBarItem.dispose();
            this._statusBarItem = undefined;
        }
    }
    async manuallyProvideToken() {
        const uriOrToken = await vscode.window.showInputBox({ prompt: 'Token', ignoreFocusOut: true });
        if (!uriOrToken) {
            onDidManuallyProvideToken.fire(undefined);
            return;
        }
        try {
            const uri = vscode.Uri.parse(uriOrToken.trim());
            if (!uri.scheme || uri.scheme === 'file') {
                throw new Error;
            }
            exports.uriHandler.handleUri(uri);
        }
        catch (e) {
            // If it doesn't look like a URI, treat it as a token.
            logger_1.default.info('Treating input as token');
            onDidManuallyProvideToken.fire(uriOrToken);
        }
    }
    async getScopes(token) {
        try {
            logger_1.default.info('Getting token scopes...');
            const result = await (0, node_fetch_1.default)('https://api.github.com', {
                headers: {
                    Authorization: `token ${token}`,
                    'User-Agent': 'Visual-Studio-Code'
                }
            });
            if (result.ok) {
                const scopes = result.headers.get('X-OAuth-Scopes');
                return scopes ? scopes.split(',').map(scope => scope.trim()) : [];
            }
            else {
                logger_1.default.error(`Getting scopes failed: ${result.statusText}`);
                throw new Error(result.statusText);
            }
        }
        catch (ex) {
            logger_1.default.error(ex.message);
            throw new Error(exports.NETWORK_ERROR);
        }
    }
    async getUserInfo(token) {
        let result;
        try {
            logger_1.default.info('Getting user info...');
            result = await (0, node_fetch_1.default)('https://api.github.com/user', {
                headers: {
                    Authorization: `token ${token}`,
                    'User-Agent': 'Visual-Studio-Code'
                }
            });
        }
        catch (ex) {
            logger_1.default.error(ex.message);
            throw new Error(exports.NETWORK_ERROR);
        }
        if (result.ok) {
            const json = await result.json();
            logger_1.default.info('Got account info!');
            return { id: json.id, accountName: json.login };
        }
        else {
            logger_1.default.error(`Getting account info failed: ${result.statusText}`);
            throw new Error(result.statusText);
        }
    }
    async checkIsEdu(token) {
        const nocors = await this.isNoCorsEnvironment();
        if (nocors) {
            return;
        }
        try {
            const result = await (0, node_fetch_1.default)('https://education.github.com/api/user', {
                headers: {
                    Authorization: `token ${token}`,
                    'faculty-check-preview': 'true',
                    'User-Agent': 'Visual-Studio-Code'
                }
            });
            if (result.ok) {
                const json = await result.json();
                /* __GDPR__
                    "session" : {
                        "isEdu": { "classification": "NonIdentifiableDemographicInfo", "purpose": "FeatureInsight" }
                    }
                */
                this.telemetryReporter.sendTelemetryEvent('session', {
                    isEdu: json.student
                        ? 'student'
                        : json.faculty
                            ? 'faculty'
                            : 'none'
                });
            }
        }
        catch (e) {
            // No-op
        }
    }
}
exports.GitHubServer = GitHubServer;


/***/ }),
/* 18 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


// ref: https://github.com/tc39/proposal-global
var getGlobal = function () {
	// the only reliable means to get the global object is
	// `Function('return this')()`
	// However, this causes CSP violations in Chrome apps.
	if (typeof self !== 'undefined') { return self; }
	if (typeof window !== 'undefined') { return window; }
	if (typeof global !== 'undefined') { return global; }
	throw new Error('unable to locate global object');
}

var global = getGlobal();

module.exports = exports = global.fetch;

// Needed for TypeScript and Webpack.
if (global.fetch) {
	exports.default = global.fetch.bind(global);
}

exports.Headers = global.Headers;
exports.Request = global.Request;
exports.Response = global.Response;

/***/ }),
/* 19 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
Object.defineProperty(exports, "__esModule", { value: true });
exports.arrayEquals = exports.promiseFromEvent = exports.onceEvent = exports.filterEvent = void 0;
const vscode_1 = __webpack_require__(1);
function filterEvent(event, filter) {
    return (listener, thisArgs = null, disposables) => event(e => filter(e) && listener.call(thisArgs, e), null, disposables);
}
exports.filterEvent = filterEvent;
function onceEvent(event) {
    return (listener, thisArgs = null, disposables) => {
        const result = event(e => {
            result.dispose();
            return listener.call(thisArgs, e);
        }, null, disposables);
        return result;
    };
}
exports.onceEvent = onceEvent;
const passthrough = (value, resolve) => resolve(value);
/**
 * Return a promise that resolves with the next emitted event, or with some future
 * event as decided by an adapter.
 *
 * If specified, the adapter is a function that will be called with
 * `(event, resolve, reject)`. It will be called once per event until it resolves or
 * rejects.
 *
 * The default adapter is the passthrough function `(value, resolve) => resolve(value)`.
 *
 * @param event the event
 * @param adapter controls resolution of the returned promise
 * @returns a promise that resolves or rejects as specified by the adapter
 */
function promiseFromEvent(event, adapter = passthrough) {
    let subscription;
    let cancel = new vscode_1.EventEmitter();
    return {
        promise: new Promise((resolve, reject) => {
            cancel.event(_ => reject());
            subscription = event((value) => {
                try {
                    Promise.resolve(adapter(value, resolve, reject))
                        .catch(reject);
                }
                catch (error) {
                    reject(error);
                }
            });
        }).then((result) => {
            subscription.dispose();
            return result;
        }, error => {
            subscription.dispose();
            throw error;
        }),
        cancel
    };
}
exports.promiseFromEvent = promiseFromEvent;
function arrayEquals(one, other, itemEquals = (a, b) => a === b) {
    if (one === other) {
        return true;
    }
    if (!one || !other) {
        return false;
    }
    if (one.length !== other.length) {
        return false;
    }
    for (let i = 0, len = one.length; i < len; i++) {
        if (!itemEquals(one[i], other[i])) {
            return false;
        }
    }
    return true;
}
exports.arrayEquals = arrayEquals;


/***/ }),
/* 20 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/


Object.defineProperty(exports, "__esModule", { value: true });

let TelemetryReporter = (function () {
	function TelemetryReporter(extensionId, extensionVersion, key) {
	}
	TelemetryReporter.prototype.updateUserOptIn = function (key) {
	};
	TelemetryReporter.prototype.createAppInsightsClient = function (key) {
	};
	TelemetryReporter.prototype.getCommonProperties = function () {
	};
	TelemetryReporter.prototype.sendTelemetryEvent = function (eventName, properties, measurements) {
	};
	TelemetryReporter.prototype.dispose = function () {
	};
	TelemetryReporter.TELEMETRY_CONFIG_ID = 'telemetry';
	TelemetryReporter.TELEMETRY_CONFIG_ENABLED_ID = 'enableTelemetry';
	return TelemetryReporter;
}());
exports.default = TelemetryReporter;


/***/ }),
/* 21 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
Object.defineProperty(exports, "__esModule", { value: true });
exports.createExperimentationService = exports.ExperimentationTelemetry = void 0;
const vscode = __webpack_require__(1);
const vscode_tas_client_1 = __webpack_require__(22);
class ExperimentationTelemetry {
    constructor(baseReporter) {
        this.baseReporter = baseReporter;
        this.sharedProperties = {};
    }
    sendTelemetryEvent(eventName, properties, measurements) {
        this.baseReporter.sendTelemetryEvent(eventName, {
            ...this.sharedProperties,
            ...properties,
        }, measurements);
    }
    sendTelemetryErrorEvent(eventName, properties, _measurements) {
        this.baseReporter.sendTelemetryErrorEvent(eventName, {
            ...this.sharedProperties,
            ...properties,
        });
    }
    setSharedProperty(name, value) {
        this.sharedProperties[name] = value;
    }
    postEvent(eventName, props) {
        const event = {};
        for (const [key, value] of props) {
            event[key] = value;
        }
        this.sendTelemetryEvent(eventName, event);
    }
    dispose() {
        return this.baseReporter.dispose();
    }
}
exports.ExperimentationTelemetry = ExperimentationTelemetry;
function getTargetPopulation() {
    switch (vscode.env.uriScheme) {
        case 'vscode':
            return vscode_tas_client_1.TargetPopulation.Public;
        case 'vscode-insiders':
            return vscode_tas_client_1.TargetPopulation.Insiders;
        case 'vscode-exploration':
            return vscode_tas_client_1.TargetPopulation.Internal;
        case 'code-oss':
            return vscode_tas_client_1.TargetPopulation.Team;
        default:
            return vscode_tas_client_1.TargetPopulation.Public;
    }
}
async function createExperimentationService(context, telemetry) {
    const id = context.extension.id;
    const version = context.extension.packageJSON.version;
    return (0, vscode_tas_client_1.getExperimentationService)(id, version, getTargetPopulation(), telemetry, context.globalState);
}
exports.createExperimentationService = createExperimentationService;


/***/ }),
/* 22 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//
Object.defineProperty(exports, "__esModule", { value: true });
var VSCodeTasClient_1 = __webpack_require__(23);
exports.getExperimentationService = VSCodeTasClient_1.getExperimentationService;
exports.getExperimentationServiceAsync = VSCodeTasClient_1.getExperimentationServiceAsync;
var VSCodeFilterProvider_1 = __webpack_require__(24);
exports.TargetPopulation = VSCodeFilterProvider_1.TargetPopulation;
//# sourceMappingURL=index.js.map

/***/ }),
/* 23 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
const VSCodeFilterProvider_1 = __webpack_require__(24);
const tas_client_1 = __webpack_require__(25);
const vscode = __webpack_require__(1);
const MementoKeyValueStorage_1 = __webpack_require__(62);
const TelemetryDisabledExperimentationService_1 = __webpack_require__(63);
const endpoint = 'https://default.exp-tas.com/vscode/ab';
const telemetryEventName = 'query-expfeature';
const featuresTelemetryPropertyName = 'VSCode.ABExp.Features';
const assignmentContextTelemetryPropertyName = 'abexp.assignmentcontext';
const storageKey = 'VSCode.ABExp.FeatureData';
const refetchInterval = 1000 * 60 * 30; // By default it's set up to 30 minutes.
/**
 *
 * @param extensionName The name of the extension.
 * @param extensionVersion The version of the extension.
 * @param telemetry Telemetry implementation.
 * @param targetPopulation An enum containing the target population ('team', 'internal', 'insiders', 'public').
 * @param memento The memento state to be used for cache.
 * @param filterProviders The filter providers.
 */
function getExperimentationService(extensionName, extensionVersion, targetPopulation, telemetry, memento, ...filterProviders) {
    if (!memento) {
        throw new Error('Memento storage was not provided.');
    }
    const config = vscode.workspace.getConfiguration('telemetry');
    const telemetryEnabled = vscode.env.isTelemetryEnabled === undefined
        ? config.get('enableTelemetry', true)
        : vscode.env.isTelemetryEnabled;
    if (!telemetryEnabled) {
        return new TelemetryDisabledExperimentationService_1.default();
    }
    const extensionFilterProvider = new VSCodeFilterProvider_1.VSCodeFilterProvider(extensionName, extensionVersion, targetPopulation);
    const providerList = [extensionFilterProvider, ...filterProviders];
    const keyValueStorage = new MementoKeyValueStorage_1.MementoKeyValueStorage(memento);
    return new tas_client_1.ExperimentationService({
        filterProviders: providerList,
        telemetry: telemetry,
        storageKey: storageKey,
        keyValueStorage: keyValueStorage,
        featuresTelemetryPropertyName: featuresTelemetryPropertyName,
        assignmentContextTelemetryPropertyName: assignmentContextTelemetryPropertyName,
        telemetryEventName: telemetryEventName,
        endpoint: endpoint,
        refetchInterval: refetchInterval,
    });
}
exports.getExperimentationService = getExperimentationService;
/**
 * Returns the experimentation service after waiting on initialize.
 *
 * @param extensionName The name of the extension.
 * @param extensionVersion The version of the extension.
 * @param telemetry Telemetry implementation.
 * @param targetPopulation An enum containing the target population ('team', 'internal', 'insiders', 'public').
 * @param memento The memento state to be used for cache.
 * @param filterProviders The filter providers.
 */
async function getExperimentationServiceAsync(extensionName, extensionVersion, targetPopulation, telemetry, memento, ...filterProviders) {
    const experimentationService = getExperimentationService(extensionName, extensionVersion, targetPopulation, telemetry, memento, ...filterProviders);
    await experimentationService.initializePromise;
    return experimentationService;
}
exports.getExperimentationServiceAsync = getExperimentationServiceAsync;
//# sourceMappingURL=VSCodeTasClient.js.map

/***/ }),
/* 24 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
const vscode = __webpack_require__(1);
/**
 * Here is where we are going to define the filters we will set.
 */
class VSCodeFilterProvider {
    constructor(extensionName, extensionVersion, targetPopulation) {
        this.extensionName = extensionName;
        this.extensionVersion = extensionVersion;
        this.targetPopulation = targetPopulation;
    }
    /**
     * Returns a version string that can be parsed into a .NET Build object
     * by removing the tag suffix (for example -dev).
     *
     * @param version Version string to be trimmed.
     */
    static trimVersionSuffix(version) {
        const regex = /\-[a-zA-Z0-9]+$/;
        const result = version.split(regex);
        return result[0];
    }
    getFilterValue(filter) {
        switch (filter) {
            case Filters.ApplicationVersion:
                return VSCodeFilterProvider.trimVersionSuffix(vscode.version);
            case Filters.Build:
                return vscode.env.appName;
            case Filters.ClientId:
                return vscode.env.machineId;
            case Filters.ExtensionName:
                return this.extensionName;
            case Filters.ExtensionVersion:
                return VSCodeFilterProvider.trimVersionSuffix(this.extensionVersion);
            case Filters.Language:
                return vscode.env.language;
            case Filters.TargetPopulation:
                return this.targetPopulation;
            default:
                return '';
        }
    }
    getFilters() {
        let filters = new Map();
        let filterValues = Object.values(Filters);
        for (let value of filterValues) {
            filters.set(value, this.getFilterValue(value));
        }
        return filters;
    }
}
exports.VSCodeFilterProvider = VSCodeFilterProvider;
/*
Based upon the official VSCode currently existing filters in the
ExP backend for the VSCode cluster.
https://experimentation.visualstudio.com/Analysis%20and%20Experimentation/_git/AnE.ExP.TAS.TachyonHost.Configuration?path=%2FConfigurations%2Fvscode%2Fvscode.json&version=GBmaster
"X-MSEdge-Market": "detection.market",
"X-FD-Corpnet": "detection.corpnet",
"X-VSCode–AppVersion": "appversion",
"X-VSCode-Build": "build",
"X-MSEdge-ClientId": "clientid",
"X-VSCode-ExtensionName": "extensionname",
"X-VSCode-ExtensionVersion": "extensionversion",
"X-VSCode-TargetPopulation": "targetpopulation",
"X-VSCode-Language": "language"
*/
/**
 * All available filters, can be updated.
 */
var Filters;
(function (Filters) {
    /**
     * The market in which the extension is distributed.
     */
    Filters["Market"] = "X-MSEdge-Market";
    /**
     * The corporation network.
     */
    Filters["CorpNet"] = "X-FD-Corpnet";
    /**
     * Version of the application which uses experimentation service.
     */
    Filters["ApplicationVersion"] = "X-VSCode-AppVersion";
    /**
     * Insiders vs Stable.
     */
    Filters["Build"] = "X-VSCode-Build";
    /**
     * Client Id which is used as primary unit for the experimentation.
     */
    Filters["ClientId"] = "X-MSEdge-ClientId";
    /**
     * Extension header.
     */
    Filters["ExtensionName"] = "X-VSCode-ExtensionName";
    /**
     * The version of the extension.
     */
    Filters["ExtensionVersion"] = "X-VSCode-ExtensionVersion";
    /**
     * The language in use by VS Code
     */
    Filters["Language"] = "X-VSCode-Language";
    /**
     * The target population.
     * This is used to separate internal, early preview, GA, etc.
     */
    Filters["TargetPopulation"] = "X-VSCode-TargetPopulation";
})(Filters = exports.Filters || (exports.Filters = {}));
/**
 * Specifies the target population for the experimentation filter.
 */
var TargetPopulation;
(function (TargetPopulation) {
    TargetPopulation["Team"] = "team";
    TargetPopulation["Internal"] = "internal";
    TargetPopulation["Insiders"] = "insider";
    TargetPopulation["Public"] = "public";
})(TargetPopulation = exports.TargetPopulation || (exports.TargetPopulation = {}));
//# sourceMappingURL=VSCodeFilterProvider.js.map

/***/ }),
/* 25 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//
Object.defineProperty(exports, "__esModule", { value: true });
var ExperimentationService_1 = __webpack_require__(26);
exports.ExperimentationService = ExperimentationService_1.ExperimentationService;
//# sourceMappingURL=index.js.map

/***/ }),
/* 26 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
const TasApiFeatureProvider_1 = __webpack_require__(27);
const AxiosHttpClient_1 = __webpack_require__(30);
const ExperimentationServiceAutoPolling_1 = __webpack_require__(58);
/**
 * Experimentation service to provide functionality of A/B experiments:
 * - reading flights;
 * - caching current set of flights;
 * - get answer on if flights are enabled.
 */
class ExperimentationService extends ExperimentationServiceAutoPolling_1.ExperimentationServiceAutoPolling {
    constructor(options) {
        super(options.telemetry, options.filterProviders || [], // Defaulted to empty array.
        options.refetchInterval != null
            ? options.refetchInterval
            : // If no fetch interval is provided, refetch functionality is turned off.
                0, options.featuresTelemetryPropertyName, options.assignmentContextTelemetryPropertyName, options.telemetryEventName, options.storageKey, options.keyValueStorage);
        this.options = options;
        this.invokeInit();
    }
    init() {
        // set feature providers to be an empty array.
        this.featureProviders = [];
        // Add WebApi feature provider.
        this.addFeatureProvider(new TasApiFeatureProvider_1.TasApiFeatureProvider(new AxiosHttpClient_1.AxiosHttpClient(this.options.endpoint), this.telemetry, this.filterProviders));
        // This will start polling the TAS.
        super.init();
    }
}
exports.ExperimentationService = ExperimentationService;
ExperimentationService.REFRESH_RATE_IN_MINUTES = 30;
//# sourceMappingURL=ExperimentationService.js.map

/***/ }),
/* 27 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
const FilteredFeatureProvider_1 = __webpack_require__(28);
/**
 * Feature provider implementation that calls the TAS web service to get the most recent active features.
 */
class TasApiFeatureProvider extends FilteredFeatureProvider_1.FilteredFeatureProvider {
    constructor(httpClient, telemetry, filterProviders) {
        super(telemetry, filterProviders);
        this.httpClient = httpClient;
        this.telemetry = telemetry;
        this.filterProviders = filterProviders;
    }
    /**
     * Method that handles fetching of latest data (in this case, flights) from the provider.
     */
    async fetch() {
        // We get the filters that will be sent as headers.
        let filters = this.getFilters();
        let headers = {};
        // Filters are handled using Map<string,any> therefore we need to
        // convert these filters into something axios can take as headers.
        for (let key of filters.keys()) {
            const filterValue = filters.get(key);
            headers[key] = filterValue;
        }
        //axios webservice call.
        let response = await this.httpClient.get({ headers: headers });
        // If we have at least one filter, we post it to telemetry event.
        if (filters.keys.length > 0) {
            this.PostEventToTelemetry(headers);
        }
        // Read the response data from the server.
        let responseData = response.data;
        let configs = responseData.Configs;
        let features = [];
        for (let c of configs) {
            if (!c.Parameters) {
                continue;
            }
            for (let key of Object.keys(c.Parameters)) {
                const featureName = key + (c.Parameters[key] ? '' : 'cf');
                if (!features.includes(featureName)) {
                    features.push(featureName);
                }
            }
        }
        return {
            features,
            assignmentContext: responseData.AssignmentContext,
            configs
        };
    }
}
exports.TasApiFeatureProvider = TasApiFeatureProvider;
//# sourceMappingURL=TasApiFeatureProvider.js.map

/***/ }),
/* 28 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
const BaseFeatureProvider_1 = __webpack_require__(29);
/**
 * Feature provider implementation that handles filters.
 */
class FilteredFeatureProvider extends BaseFeatureProvider_1.BaseFeatureProvider {
    constructor(telemetry, filterProviders) {
        super(telemetry);
        this.telemetry = telemetry;
        this.filterProviders = filterProviders;
        this.cachedTelemetryEvents = [];
    }
    getFilters() {
        // We get the filters that will be sent as headers.
        let filters = new Map();
        for (let filter of this.filterProviders) {
            let filterHeaders = filter.getFilters();
            for (let key of filterHeaders.keys()) {
                // Headers can be overridden by custom filters.
                // That's why a check isn't done to see if the header already exists, the value is just set.
                let filterValue = filterHeaders.get(key);
                filters.set(key, filterValue);
            }
        }
        return filters;
    }
    PostEventToTelemetry(headers) {
        /**
         * If these headers have already been posted, we skip from posting them again..
         */
        if (this.cachedTelemetryEvents.includes(headers)) {
            return;
        }
        const jsonHeaders = JSON.stringify(headers);
        this.telemetry.postEvent('report-headers', new Map([['ABExp.headers', jsonHeaders]]));
        /**
         * We cache the flight so we don't post it again.
         */
        this.cachedTelemetryEvents.push(headers);
    }
}
exports.FilteredFeatureProvider = FilteredFeatureProvider;
//# sourceMappingURL=FilteredFeatureProvider.js.map

/***/ }),
/* 29 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
/**
 * Abstract class for Feature Provider Implementation.
 */
class BaseFeatureProvider {
    /**
     * @param telemetry The telemetry implementation.
     */
    constructor(telemetry) {
        this.telemetry = telemetry;
        this.isFetching = false;
    }
    /**
     * Method that wraps the fetch method in order to re-use the fetch promise if needed.
     * @param headers The headers to be used on the fetch method.
     */
    async getFeatures() {
        if (this.isFetching && this.fetchPromise) {
            return this.fetchPromise;
        }
        this.fetchPromise = this.fetch();
        let features = await this.fetchPromise;
        this.isFetching = false;
        this.fetchPromise = undefined;
        return features;
    }
}
exports.BaseFeatureProvider = BaseFeatureProvider;
//# sourceMappingURL=BaseFeatureProvider.js.map

/***/ }),
/* 30 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
const axios_1 = __webpack_require__(31);
class AxiosHttpClient {
    constructor(endpoint) {
        this.endpoint = endpoint;
    }
    get(config) {
        return axios_1.default.get(this.endpoint, Object.assign(Object.assign({}, config), { proxy: false }));
    }
}
exports.AxiosHttpClient = AxiosHttpClient;
//# sourceMappingURL=AxiosHttpClient.js.map

/***/ }),
/* 31 */
/***/ (function(module, exports, __webpack_require__) {

module.exports = __webpack_require__(32);

/***/ }),
/* 32 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var utils = __webpack_require__(33);
var bind = __webpack_require__(34);
var Axios = __webpack_require__(35);
var mergeConfig = __webpack_require__(53);
var defaults = __webpack_require__(41);

/**
 * Create an instance of Axios
 *
 * @param {Object} defaultConfig The default config for the instance
 * @return {Axios} A new instance of Axios
 */
function createInstance(defaultConfig) {
  var context = new Axios(defaultConfig);
  var instance = bind(Axios.prototype.request, context);

  // Copy axios.prototype to instance
  utils.extend(instance, Axios.prototype, context);

  // Copy context to instance
  utils.extend(instance, context);

  return instance;
}

// Create the default instance to be exported
var axios = createInstance(defaults);

// Expose Axios class to allow class inheritance
axios.Axios = Axios;

// Factory for creating new instances
axios.create = function create(instanceConfig) {
  return createInstance(mergeConfig(axios.defaults, instanceConfig));
};

// Expose Cancel & CancelToken
axios.Cancel = __webpack_require__(54);
axios.CancelToken = __webpack_require__(55);
axios.isCancel = __webpack_require__(40);

// Expose all/spread
axios.all = function all(promises) {
  return Promise.all(promises);
};
axios.spread = __webpack_require__(56);

// Expose isAxiosError
axios.isAxiosError = __webpack_require__(57);

module.exports = axios;

// Allow use of default import syntax in TypeScript
module.exports.default = axios;


/***/ }),
/* 33 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var bind = __webpack_require__(34);

/*global toString:true*/

// utils is a library of generic helper functions non-specific to axios

var toString = Object.prototype.toString;

/**
 * Determine if a value is an Array
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is an Array, otherwise false
 */
function isArray(val) {
  return toString.call(val) === '[object Array]';
}

/**
 * Determine if a value is undefined
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if the value is undefined, otherwise false
 */
function isUndefined(val) {
  return typeof val === 'undefined';
}

/**
 * Determine if a value is a Buffer
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is a Buffer, otherwise false
 */
function isBuffer(val) {
  return val !== null && !isUndefined(val) && val.constructor !== null && !isUndefined(val.constructor)
    && typeof val.constructor.isBuffer === 'function' && val.constructor.isBuffer(val);
}

/**
 * Determine if a value is an ArrayBuffer
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is an ArrayBuffer, otherwise false
 */
function isArrayBuffer(val) {
  return toString.call(val) === '[object ArrayBuffer]';
}

/**
 * Determine if a value is a FormData
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is an FormData, otherwise false
 */
function isFormData(val) {
  return (typeof FormData !== 'undefined') && (val instanceof FormData);
}

/**
 * Determine if a value is a view on an ArrayBuffer
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is a view on an ArrayBuffer, otherwise false
 */
function isArrayBufferView(val) {
  var result;
  if ((typeof ArrayBuffer !== 'undefined') && (ArrayBuffer.isView)) {
    result = ArrayBuffer.isView(val);
  } else {
    result = (val) && (val.buffer) && (val.buffer instanceof ArrayBuffer);
  }
  return result;
}

/**
 * Determine if a value is a String
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is a String, otherwise false
 */
function isString(val) {
  return typeof val === 'string';
}

/**
 * Determine if a value is a Number
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is a Number, otherwise false
 */
function isNumber(val) {
  return typeof val === 'number';
}

/**
 * Determine if a value is an Object
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is an Object, otherwise false
 */
function isObject(val) {
  return val !== null && typeof val === 'object';
}

/**
 * Determine if a value is a plain Object
 *
 * @param {Object} val The value to test
 * @return {boolean} True if value is a plain Object, otherwise false
 */
function isPlainObject(val) {
  if (toString.call(val) !== '[object Object]') {
    return false;
  }

  var prototype = Object.getPrototypeOf(val);
  return prototype === null || prototype === Object.prototype;
}

/**
 * Determine if a value is a Date
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is a Date, otherwise false
 */
function isDate(val) {
  return toString.call(val) === '[object Date]';
}

/**
 * Determine if a value is a File
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is a File, otherwise false
 */
function isFile(val) {
  return toString.call(val) === '[object File]';
}

/**
 * Determine if a value is a Blob
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is a Blob, otherwise false
 */
function isBlob(val) {
  return toString.call(val) === '[object Blob]';
}

/**
 * Determine if a value is a Function
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is a Function, otherwise false
 */
function isFunction(val) {
  return toString.call(val) === '[object Function]';
}

/**
 * Determine if a value is a Stream
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is a Stream, otherwise false
 */
function isStream(val) {
  return isObject(val) && isFunction(val.pipe);
}

/**
 * Determine if a value is a URLSearchParams object
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is a URLSearchParams object, otherwise false
 */
function isURLSearchParams(val) {
  return typeof URLSearchParams !== 'undefined' && val instanceof URLSearchParams;
}

/**
 * Trim excess whitespace off the beginning and end of a string
 *
 * @param {String} str The String to trim
 * @returns {String} The String freed of excess whitespace
 */
function trim(str) {
  return str.replace(/^\s*/, '').replace(/\s*$/, '');
}

/**
 * Determine if we're running in a standard browser environment
 *
 * This allows axios to run in a web worker, and react-native.
 * Both environments support XMLHttpRequest, but not fully standard globals.
 *
 * web workers:
 *  typeof window -> undefined
 *  typeof document -> undefined
 *
 * react-native:
 *  navigator.product -> 'ReactNative'
 * nativescript
 *  navigator.product -> 'NativeScript' or 'NS'
 */
function isStandardBrowserEnv() {
  if (typeof navigator !== 'undefined' && (navigator.product === 'ReactNative' ||
                                           navigator.product === 'NativeScript' ||
                                           navigator.product === 'NS')) {
    return false;
  }
  return (
    typeof window !== 'undefined' &&
    typeof document !== 'undefined'
  );
}

/**
 * Iterate over an Array or an Object invoking a function for each item.
 *
 * If `obj` is an Array callback will be called passing
 * the value, index, and complete array for each item.
 *
 * If 'obj' is an Object callback will be called passing
 * the value, key, and complete object for each property.
 *
 * @param {Object|Array} obj The object to iterate
 * @param {Function} fn The callback to invoke for each item
 */
function forEach(obj, fn) {
  // Don't bother if no value provided
  if (obj === null || typeof obj === 'undefined') {
    return;
  }

  // Force an array if not already something iterable
  if (typeof obj !== 'object') {
    /*eslint no-param-reassign:0*/
    obj = [obj];
  }

  if (isArray(obj)) {
    // Iterate over array values
    for (var i = 0, l = obj.length; i < l; i++) {
      fn.call(null, obj[i], i, obj);
    }
  } else {
    // Iterate over object keys
    for (var key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        fn.call(null, obj[key], key, obj);
      }
    }
  }
}

/**
 * Accepts varargs expecting each argument to be an object, then
 * immutably merges the properties of each object and returns result.
 *
 * When multiple objects contain the same key the later object in
 * the arguments list will take precedence.
 *
 * Example:
 *
 * ```js
 * var result = merge({foo: 123}, {foo: 456});
 * console.log(result.foo); // outputs 456
 * ```
 *
 * @param {Object} obj1 Object to merge
 * @returns {Object} Result of all merge properties
 */
function merge(/* obj1, obj2, obj3, ... */) {
  var result = {};
  function assignValue(val, key) {
    if (isPlainObject(result[key]) && isPlainObject(val)) {
      result[key] = merge(result[key], val);
    } else if (isPlainObject(val)) {
      result[key] = merge({}, val);
    } else if (isArray(val)) {
      result[key] = val.slice();
    } else {
      result[key] = val;
    }
  }

  for (var i = 0, l = arguments.length; i < l; i++) {
    forEach(arguments[i], assignValue);
  }
  return result;
}

/**
 * Extends object a by mutably adding to it the properties of object b.
 *
 * @param {Object} a The object to be extended
 * @param {Object} b The object to copy properties from
 * @param {Object} thisArg The object to bind function to
 * @return {Object} The resulting value of object a
 */
function extend(a, b, thisArg) {
  forEach(b, function assignValue(val, key) {
    if (thisArg && typeof val === 'function') {
      a[key] = bind(val, thisArg);
    } else {
      a[key] = val;
    }
  });
  return a;
}

/**
 * Remove byte order marker. This catches EF BB BF (the UTF-8 BOM)
 *
 * @param {string} content with BOM
 * @return {string} content value without BOM
 */
function stripBOM(content) {
  if (content.charCodeAt(0) === 0xFEFF) {
    content = content.slice(1);
  }
  return content;
}

module.exports = {
  isArray: isArray,
  isArrayBuffer: isArrayBuffer,
  isBuffer: isBuffer,
  isFormData: isFormData,
  isArrayBufferView: isArrayBufferView,
  isString: isString,
  isNumber: isNumber,
  isObject: isObject,
  isPlainObject: isPlainObject,
  isUndefined: isUndefined,
  isDate: isDate,
  isFile: isFile,
  isBlob: isBlob,
  isFunction: isFunction,
  isStream: isStream,
  isURLSearchParams: isURLSearchParams,
  isStandardBrowserEnv: isStandardBrowserEnv,
  forEach: forEach,
  merge: merge,
  extend: extend,
  trim: trim,
  stripBOM: stripBOM
};


/***/ }),
/* 34 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = function bind(fn, thisArg) {
  return function wrap() {
    var args = new Array(arguments.length);
    for (var i = 0; i < args.length; i++) {
      args[i] = arguments[i];
    }
    return fn.apply(thisArg, args);
  };
};


/***/ }),
/* 35 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var utils = __webpack_require__(33);
var buildURL = __webpack_require__(36);
var InterceptorManager = __webpack_require__(37);
var dispatchRequest = __webpack_require__(38);
var mergeConfig = __webpack_require__(53);

/**
 * Create a new instance of Axios
 *
 * @param {Object} instanceConfig The default config for the instance
 */
function Axios(instanceConfig) {
  this.defaults = instanceConfig;
  this.interceptors = {
    request: new InterceptorManager(),
    response: new InterceptorManager()
  };
}

/**
 * Dispatch a request
 *
 * @param {Object} config The config specific for this request (merged with this.defaults)
 */
Axios.prototype.request = function request(config) {
  /*eslint no-param-reassign:0*/
  // Allow for axios('example/url'[, config]) a la fetch API
  if (typeof config === 'string') {
    config = arguments[1] || {};
    config.url = arguments[0];
  } else {
    config = config || {};
  }

  config = mergeConfig(this.defaults, config);

  // Set config.method
  if (config.method) {
    config.method = config.method.toLowerCase();
  } else if (this.defaults.method) {
    config.method = this.defaults.method.toLowerCase();
  } else {
    config.method = 'get';
  }

  // Hook up interceptors middleware
  var chain = [dispatchRequest, undefined];
  var promise = Promise.resolve(config);

  this.interceptors.request.forEach(function unshiftRequestInterceptors(interceptor) {
    chain.unshift(interceptor.fulfilled, interceptor.rejected);
  });

  this.interceptors.response.forEach(function pushResponseInterceptors(interceptor) {
    chain.push(interceptor.fulfilled, interceptor.rejected);
  });

  while (chain.length) {
    promise = promise.then(chain.shift(), chain.shift());
  }

  return promise;
};

Axios.prototype.getUri = function getUri(config) {
  config = mergeConfig(this.defaults, config);
  return buildURL(config.url, config.params, config.paramsSerializer).replace(/^\?/, '');
};

// Provide aliases for supported request methods
utils.forEach(['delete', 'get', 'head', 'options'], function forEachMethodNoData(method) {
  /*eslint func-names:0*/
  Axios.prototype[method] = function(url, config) {
    return this.request(mergeConfig(config || {}, {
      method: method,
      url: url,
      data: (config || {}).data
    }));
  };
});

utils.forEach(['post', 'put', 'patch'], function forEachMethodWithData(method) {
  /*eslint func-names:0*/
  Axios.prototype[method] = function(url, data, config) {
    return this.request(mergeConfig(config || {}, {
      method: method,
      url: url,
      data: data
    }));
  };
});

module.exports = Axios;


/***/ }),
/* 36 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var utils = __webpack_require__(33);

function encode(val) {
  return encodeURIComponent(val).
    replace(/%3A/gi, ':').
    replace(/%24/g, '$').
    replace(/%2C/gi, ',').
    replace(/%20/g, '+').
    replace(/%5B/gi, '[').
    replace(/%5D/gi, ']');
}

/**
 * Build a URL by appending params to the end
 *
 * @param {string} url The base of the url (e.g., http://www.google.com)
 * @param {object} [params] The params to be appended
 * @returns {string} The formatted url
 */
module.exports = function buildURL(url, params, paramsSerializer) {
  /*eslint no-param-reassign:0*/
  if (!params) {
    return url;
  }

  var serializedParams;
  if (paramsSerializer) {
    serializedParams = paramsSerializer(params);
  } else if (utils.isURLSearchParams(params)) {
    serializedParams = params.toString();
  } else {
    var parts = [];

    utils.forEach(params, function serialize(val, key) {
      if (val === null || typeof val === 'undefined') {
        return;
      }

      if (utils.isArray(val)) {
        key = key + '[]';
      } else {
        val = [val];
      }

      utils.forEach(val, function parseValue(v) {
        if (utils.isDate(v)) {
          v = v.toISOString();
        } else if (utils.isObject(v)) {
          v = JSON.stringify(v);
        }
        parts.push(encode(key) + '=' + encode(v));
      });
    });

    serializedParams = parts.join('&');
  }

  if (serializedParams) {
    var hashmarkIndex = url.indexOf('#');
    if (hashmarkIndex !== -1) {
      url = url.slice(0, hashmarkIndex);
    }

    url += (url.indexOf('?') === -1 ? '?' : '&') + serializedParams;
  }

  return url;
};


/***/ }),
/* 37 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var utils = __webpack_require__(33);

function InterceptorManager() {
  this.handlers = [];
}

/**
 * Add a new interceptor to the stack
 *
 * @param {Function} fulfilled The function to handle `then` for a `Promise`
 * @param {Function} rejected The function to handle `reject` for a `Promise`
 *
 * @return {Number} An ID used to remove interceptor later
 */
InterceptorManager.prototype.use = function use(fulfilled, rejected) {
  this.handlers.push({
    fulfilled: fulfilled,
    rejected: rejected
  });
  return this.handlers.length - 1;
};

/**
 * Remove an interceptor from the stack
 *
 * @param {Number} id The ID that was returned by `use`
 */
InterceptorManager.prototype.eject = function eject(id) {
  if (this.handlers[id]) {
    this.handlers[id] = null;
  }
};

/**
 * Iterate over all the registered interceptors
 *
 * This method is particularly useful for skipping over any
 * interceptors that may have become `null` calling `eject`.
 *
 * @param {Function} fn The function to call for each interceptor
 */
InterceptorManager.prototype.forEach = function forEach(fn) {
  utils.forEach(this.handlers, function forEachHandler(h) {
    if (h !== null) {
      fn(h);
    }
  });
};

module.exports = InterceptorManager;


/***/ }),
/* 38 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var utils = __webpack_require__(33);
var transformData = __webpack_require__(39);
var isCancel = __webpack_require__(40);
var defaults = __webpack_require__(41);

/**
 * Throws a `Cancel` if cancellation has been requested.
 */
function throwIfCancellationRequested(config) {
  if (config.cancelToken) {
    config.cancelToken.throwIfRequested();
  }
}

/**
 * Dispatch a request to the server using the configured adapter.
 *
 * @param {object} config The config that is to be used for the request
 * @returns {Promise} The Promise to be fulfilled
 */
module.exports = function dispatchRequest(config) {
  throwIfCancellationRequested(config);

  // Ensure headers exist
  config.headers = config.headers || {};

  // Transform request data
  config.data = transformData(
    config.data,
    config.headers,
    config.transformRequest
  );

  // Flatten headers
  config.headers = utils.merge(
    config.headers.common || {},
    config.headers[config.method] || {},
    config.headers
  );

  utils.forEach(
    ['delete', 'get', 'head', 'post', 'put', 'patch', 'common'],
    function cleanHeaderConfig(method) {
      delete config.headers[method];
    }
  );

  var adapter = config.adapter || defaults.adapter;

  return adapter(config).then(function onAdapterResolution(response) {
    throwIfCancellationRequested(config);

    // Transform response data
    response.data = transformData(
      response.data,
      response.headers,
      config.transformResponse
    );

    return response;
  }, function onAdapterRejection(reason) {
    if (!isCancel(reason)) {
      throwIfCancellationRequested(config);

      // Transform response data
      if (reason && reason.response) {
        reason.response.data = transformData(
          reason.response.data,
          reason.response.headers,
          config.transformResponse
        );
      }
    }

    return Promise.reject(reason);
  });
};


/***/ }),
/* 39 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var utils = __webpack_require__(33);

/**
 * Transform the data for a request or a response
 *
 * @param {Object|String} data The data to be transformed
 * @param {Array} headers The headers for the request or response
 * @param {Array|Function} fns A single function or Array of functions
 * @returns {*} The resulting transformed data
 */
module.exports = function transformData(data, headers, fns) {
  /*eslint no-param-reassign:0*/
  utils.forEach(fns, function transform(fn) {
    data = fn(data, headers);
  });

  return data;
};


/***/ }),
/* 40 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = function isCancel(value) {
  return !!(value && value.__CANCEL__);
};


/***/ }),
/* 41 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var utils = __webpack_require__(33);
var normalizeHeaderName = __webpack_require__(42);

var DEFAULT_CONTENT_TYPE = {
  'Content-Type': 'application/x-www-form-urlencoded'
};

function setContentTypeIfUnset(headers, value) {
  if (!utils.isUndefined(headers) && utils.isUndefined(headers['Content-Type'])) {
    headers['Content-Type'] = value;
  }
}

function getDefaultAdapter() {
  var adapter;
  if (typeof XMLHttpRequest !== 'undefined') {
    // For browsers use XHR adapter
    adapter = __webpack_require__(43);
  } else if (typeof process !== 'undefined' && Object.prototype.toString.call(process) === '[object process]') {
    // For node use HTTP adapter
    adapter = __webpack_require__(43);
  }
  return adapter;
}

var defaults = {
  adapter: getDefaultAdapter(),

  transformRequest: [function transformRequest(data, headers) {
    normalizeHeaderName(headers, 'Accept');
    normalizeHeaderName(headers, 'Content-Type');
    if (utils.isFormData(data) ||
      utils.isArrayBuffer(data) ||
      utils.isBuffer(data) ||
      utils.isStream(data) ||
      utils.isFile(data) ||
      utils.isBlob(data)
    ) {
      return data;
    }
    if (utils.isArrayBufferView(data)) {
      return data.buffer;
    }
    if (utils.isURLSearchParams(data)) {
      setContentTypeIfUnset(headers, 'application/x-www-form-urlencoded;charset=utf-8');
      return data.toString();
    }
    if (utils.isObject(data)) {
      setContentTypeIfUnset(headers, 'application/json;charset=utf-8');
      return JSON.stringify(data);
    }
    return data;
  }],

  transformResponse: [function transformResponse(data) {
    /*eslint no-param-reassign:0*/
    if (typeof data === 'string') {
      try {
        data = JSON.parse(data);
      } catch (e) { /* Ignore */ }
    }
    return data;
  }],

  /**
   * A timeout in milliseconds to abort a request. If set to 0 (default) a
   * timeout is not created.
   */
  timeout: 0,

  xsrfCookieName: 'XSRF-TOKEN',
  xsrfHeaderName: 'X-XSRF-TOKEN',

  maxContentLength: -1,
  maxBodyLength: -1,

  validateStatus: function validateStatus(status) {
    return status >= 200 && status < 300;
  }
};

defaults.headers = {
  common: {
    'Accept': 'application/json, text/plain, */*'
  }
};

utils.forEach(['delete', 'get', 'head'], function forEachMethodNoData(method) {
  defaults.headers[method] = {};
});

utils.forEach(['post', 'put', 'patch'], function forEachMethodWithData(method) {
  defaults.headers[method] = utils.merge(DEFAULT_CONTENT_TYPE);
});

module.exports = defaults;


/***/ }),
/* 42 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var utils = __webpack_require__(33);

module.exports = function normalizeHeaderName(headers, normalizedName) {
  utils.forEach(headers, function processHeader(value, name) {
    if (name !== normalizedName && name.toUpperCase() === normalizedName.toUpperCase()) {
      headers[normalizedName] = value;
      delete headers[name];
    }
  });
};


/***/ }),
/* 43 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var utils = __webpack_require__(33);
var settle = __webpack_require__(44);
var cookies = __webpack_require__(47);
var buildURL = __webpack_require__(36);
var buildFullPath = __webpack_require__(48);
var parseHeaders = __webpack_require__(51);
var isURLSameOrigin = __webpack_require__(52);
var createError = __webpack_require__(45);

module.exports = function xhrAdapter(config) {
  return new Promise(function dispatchXhrRequest(resolve, reject) {
    var requestData = config.data;
    var requestHeaders = config.headers;

    if (utils.isFormData(requestData)) {
      delete requestHeaders['Content-Type']; // Let the browser set it
    }

    var request = new XMLHttpRequest();

    // HTTP basic authentication
    if (config.auth) {
      var username = config.auth.username || '';
      var password = config.auth.password ? unescape(encodeURIComponent(config.auth.password)) : '';
      requestHeaders.Authorization = 'Basic ' + btoa(username + ':' + password);
    }

    var fullPath = buildFullPath(config.baseURL, config.url);
    request.open(config.method.toUpperCase(), buildURL(fullPath, config.params, config.paramsSerializer), true);

    // Set the request timeout in MS
    request.timeout = config.timeout;

    // Listen for ready state
    request.onreadystatechange = function handleLoad() {
      if (!request || request.readyState !== 4) {
        return;
      }

      // The request errored out and we didn't get a response, this will be
      // handled by onerror instead
      // With one exception: request that using file: protocol, most browsers
      // will return status as 0 even though it's a successful request
      if (request.status === 0 && !(request.responseURL && request.responseURL.indexOf('file:') === 0)) {
        return;
      }

      // Prepare the response
      var responseHeaders = 'getAllResponseHeaders' in request ? parseHeaders(request.getAllResponseHeaders()) : null;
      var responseData = !config.responseType || config.responseType === 'text' ? request.responseText : request.response;
      var response = {
        data: responseData,
        status: request.status,
        statusText: request.statusText,
        headers: responseHeaders,
        config: config,
        request: request
      };

      settle(resolve, reject, response);

      // Clean up request
      request = null;
    };

    // Handle browser request cancellation (as opposed to a manual cancellation)
    request.onabort = function handleAbort() {
      if (!request) {
        return;
      }

      reject(createError('Request aborted', config, 'ECONNABORTED', request));

      // Clean up request
      request = null;
    };

    // Handle low level network errors
    request.onerror = function handleError() {
      // Real errors are hidden from us by the browser
      // onerror should only fire if it's a network error
      reject(createError('Network Error', config, null, request));

      // Clean up request
      request = null;
    };

    // Handle timeout
    request.ontimeout = function handleTimeout() {
      var timeoutErrorMessage = 'timeout of ' + config.timeout + 'ms exceeded';
      if (config.timeoutErrorMessage) {
        timeoutErrorMessage = config.timeoutErrorMessage;
      }
      reject(createError(timeoutErrorMessage, config, 'ECONNABORTED',
        request));

      // Clean up request
      request = null;
    };

    // Add xsrf header
    // This is only done if running in a standard browser environment.
    // Specifically not if we're in a web worker, or react-native.
    if (utils.isStandardBrowserEnv()) {
      // Add xsrf header
      var xsrfValue = (config.withCredentials || isURLSameOrigin(fullPath)) && config.xsrfCookieName ?
        cookies.read(config.xsrfCookieName) :
        undefined;

      if (xsrfValue) {
        requestHeaders[config.xsrfHeaderName] = xsrfValue;
      }
    }

    // Add headers to the request
    if ('setRequestHeader' in request) {
      utils.forEach(requestHeaders, function setRequestHeader(val, key) {
        if (typeof requestData === 'undefined' && key.toLowerCase() === 'content-type') {
          // Remove Content-Type if data is undefined
          delete requestHeaders[key];
        } else {
          // Otherwise add header to the request
          request.setRequestHeader(key, val);
        }
      });
    }

    // Add withCredentials to request if needed
    if (!utils.isUndefined(config.withCredentials)) {
      request.withCredentials = !!config.withCredentials;
    }

    // Add responseType to request if needed
    if (config.responseType) {
      try {
        request.responseType = config.responseType;
      } catch (e) {
        // Expected DOMException thrown by browsers not compatible XMLHttpRequest Level 2.
        // But, this can be suppressed for 'json' type as it can be parsed by default 'transformResponse' function.
        if (config.responseType !== 'json') {
          throw e;
        }
      }
    }

    // Handle progress if needed
    if (typeof config.onDownloadProgress === 'function') {
      request.addEventListener('progress', config.onDownloadProgress);
    }

    // Not all browsers support upload events
    if (typeof config.onUploadProgress === 'function' && request.upload) {
      request.upload.addEventListener('progress', config.onUploadProgress);
    }

    if (config.cancelToken) {
      // Handle cancellation
      config.cancelToken.promise.then(function onCanceled(cancel) {
        if (!request) {
          return;
        }

        request.abort();
        reject(cancel);
        // Clean up request
        request = null;
      });
    }

    if (!requestData) {
      requestData = null;
    }

    // Send the request
    request.send(requestData);
  });
};


/***/ }),
/* 44 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var createError = __webpack_require__(45);

/**
 * Resolve or reject a Promise based on response status.
 *
 * @param {Function} resolve A function that resolves the promise.
 * @param {Function} reject A function that rejects the promise.
 * @param {object} response The response.
 */
module.exports = function settle(resolve, reject, response) {
  var validateStatus = response.config.validateStatus;
  if (!response.status || !validateStatus || validateStatus(response.status)) {
    resolve(response);
  } else {
    reject(createError(
      'Request failed with status code ' + response.status,
      response.config,
      null,
      response.request,
      response
    ));
  }
};


/***/ }),
/* 45 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var enhanceError = __webpack_require__(46);

/**
 * Create an Error with the specified message, config, error code, request and response.
 *
 * @param {string} message The error message.
 * @param {Object} config The config.
 * @param {string} [code] The error code (for example, 'ECONNABORTED').
 * @param {Object} [request] The request.
 * @param {Object} [response] The response.
 * @returns {Error} The created error.
 */
module.exports = function createError(message, config, code, request, response) {
  var error = new Error(message);
  return enhanceError(error, config, code, request, response);
};


/***/ }),
/* 46 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Update an Error with the specified config, error code, and response.
 *
 * @param {Error} error The error to update.
 * @param {Object} config The config.
 * @param {string} [code] The error code (for example, 'ECONNABORTED').
 * @param {Object} [request] The request.
 * @param {Object} [response] The response.
 * @returns {Error} The error.
 */
module.exports = function enhanceError(error, config, code, request, response) {
  error.config = config;
  if (code) {
    error.code = code;
  }

  error.request = request;
  error.response = response;
  error.isAxiosError = true;

  error.toJSON = function toJSON() {
    return {
      // Standard
      message: this.message,
      name: this.name,
      // Microsoft
      description: this.description,
      number: this.number,
      // Mozilla
      fileName: this.fileName,
      lineNumber: this.lineNumber,
      columnNumber: this.columnNumber,
      stack: this.stack,
      // Axios
      config: this.config,
      code: this.code
    };
  };
  return error;
};


/***/ }),
/* 47 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var utils = __webpack_require__(33);

module.exports = (
  utils.isStandardBrowserEnv() ?

  // Standard browser envs support document.cookie
    (function standardBrowserEnv() {
      return {
        write: function write(name, value, expires, path, domain, secure) {
          var cookie = [];
          cookie.push(name + '=' + encodeURIComponent(value));

          if (utils.isNumber(expires)) {
            cookie.push('expires=' + new Date(expires).toGMTString());
          }

          if (utils.isString(path)) {
            cookie.push('path=' + path);
          }

          if (utils.isString(domain)) {
            cookie.push('domain=' + domain);
          }

          if (secure === true) {
            cookie.push('secure');
          }

          document.cookie = cookie.join('; ');
        },

        read: function read(name) {
          var match = document.cookie.match(new RegExp('(^|;\\s*)(' + name + ')=([^;]*)'));
          return (match ? decodeURIComponent(match[3]) : null);
        },

        remove: function remove(name) {
          this.write(name, '', Date.now() - 86400000);
        }
      };
    })() :

  // Non standard browser env (web workers, react-native) lack needed support.
    (function nonStandardBrowserEnv() {
      return {
        write: function write() {},
        read: function read() { return null; },
        remove: function remove() {}
      };
    })()
);


/***/ }),
/* 48 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var isAbsoluteURL = __webpack_require__(49);
var combineURLs = __webpack_require__(50);

/**
 * Creates a new URL by combining the baseURL with the requestedURL,
 * only when the requestedURL is not already an absolute URL.
 * If the requestURL is absolute, this function returns the requestedURL untouched.
 *
 * @param {string} baseURL The base URL
 * @param {string} requestedURL Absolute or relative URL to combine
 * @returns {string} The combined full path
 */
module.exports = function buildFullPath(baseURL, requestedURL) {
  if (baseURL && !isAbsoluteURL(requestedURL)) {
    return combineURLs(baseURL, requestedURL);
  }
  return requestedURL;
};


/***/ }),
/* 49 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Determines whether the specified URL is absolute
 *
 * @param {string} url The URL to test
 * @returns {boolean} True if the specified URL is absolute, otherwise false
 */
module.exports = function isAbsoluteURL(url) {
  // A URL is considered absolute if it begins with "<scheme>://" or "//" (protocol-relative URL).
  // RFC 3986 defines scheme name as a sequence of characters beginning with a letter and followed
  // by any combination of letters, digits, plus, period, or hyphen.
  return /^([a-z][a-z\d\+\-\.]*:)?\/\//i.test(url);
};


/***/ }),
/* 50 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Creates a new URL by combining the specified URLs
 *
 * @param {string} baseURL The base URL
 * @param {string} relativeURL The relative URL
 * @returns {string} The combined URL
 */
module.exports = function combineURLs(baseURL, relativeURL) {
  return relativeURL
    ? baseURL.replace(/\/+$/, '') + '/' + relativeURL.replace(/^\/+/, '')
    : baseURL;
};


/***/ }),
/* 51 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var utils = __webpack_require__(33);

// Headers whose duplicates are ignored by node
// c.f. https://nodejs.org/api/http.html#http_message_headers
var ignoreDuplicateOf = [
  'age', 'authorization', 'content-length', 'content-type', 'etag',
  'expires', 'from', 'host', 'if-modified-since', 'if-unmodified-since',
  'last-modified', 'location', 'max-forwards', 'proxy-authorization',
  'referer', 'retry-after', 'user-agent'
];

/**
 * Parse headers into an object
 *
 * ```
 * Date: Wed, 27 Aug 2014 08:58:49 GMT
 * Content-Type: application/json
 * Connection: keep-alive
 * Transfer-Encoding: chunked
 * ```
 *
 * @param {String} headers Headers needing to be parsed
 * @returns {Object} Headers parsed into an object
 */
module.exports = function parseHeaders(headers) {
  var parsed = {};
  var key;
  var val;
  var i;

  if (!headers) { return parsed; }

  utils.forEach(headers.split('\n'), function parser(line) {
    i = line.indexOf(':');
    key = utils.trim(line.substr(0, i)).toLowerCase();
    val = utils.trim(line.substr(i + 1));

    if (key) {
      if (parsed[key] && ignoreDuplicateOf.indexOf(key) >= 0) {
        return;
      }
      if (key === 'set-cookie') {
        parsed[key] = (parsed[key] ? parsed[key] : []).concat([val]);
      } else {
        parsed[key] = parsed[key] ? parsed[key] + ', ' + val : val;
      }
    }
  });

  return parsed;
};


/***/ }),
/* 52 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var utils = __webpack_require__(33);

module.exports = (
  utils.isStandardBrowserEnv() ?

  // Standard browser envs have full support of the APIs needed to test
  // whether the request URL is of the same origin as current location.
    (function standardBrowserEnv() {
      var msie = /(msie|trident)/i.test(navigator.userAgent);
      var urlParsingNode = document.createElement('a');
      var originURL;

      /**
    * Parse a URL to discover it's components
    *
    * @param {String} url The URL to be parsed
    * @returns {Object}
    */
      function resolveURL(url) {
        var href = url;

        if (msie) {
        // IE needs attribute set twice to normalize properties
          urlParsingNode.setAttribute('href', href);
          href = urlParsingNode.href;
        }

        urlParsingNode.setAttribute('href', href);

        // urlParsingNode provides the UrlUtils interface - http://url.spec.whatwg.org/#urlutils
        return {
          href: urlParsingNode.href,
          protocol: urlParsingNode.protocol ? urlParsingNode.protocol.replace(/:$/, '') : '',
          host: urlParsingNode.host,
          search: urlParsingNode.search ? urlParsingNode.search.replace(/^\?/, '') : '',
          hash: urlParsingNode.hash ? urlParsingNode.hash.replace(/^#/, '') : '',
          hostname: urlParsingNode.hostname,
          port: urlParsingNode.port,
          pathname: (urlParsingNode.pathname.charAt(0) === '/') ?
            urlParsingNode.pathname :
            '/' + urlParsingNode.pathname
        };
      }

      originURL = resolveURL(window.location.href);

      /**
    * Determine if a URL shares the same origin as the current location
    *
    * @param {String} requestURL The URL to test
    * @returns {boolean} True if URL shares the same origin, otherwise false
    */
      return function isURLSameOrigin(requestURL) {
        var parsed = (utils.isString(requestURL)) ? resolveURL(requestURL) : requestURL;
        return (parsed.protocol === originURL.protocol &&
            parsed.host === originURL.host);
      };
    })() :

  // Non standard browser envs (web workers, react-native) lack needed support.
    (function nonStandardBrowserEnv() {
      return function isURLSameOrigin() {
        return true;
      };
    })()
);


/***/ }),
/* 53 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var utils = __webpack_require__(33);

/**
 * Config-specific merge-function which creates a new config-object
 * by merging two configuration objects together.
 *
 * @param {Object} config1
 * @param {Object} config2
 * @returns {Object} New object resulting from merging config2 to config1
 */
module.exports = function mergeConfig(config1, config2) {
  // eslint-disable-next-line no-param-reassign
  config2 = config2 || {};
  var config = {};

  var valueFromConfig2Keys = ['url', 'method', 'data'];
  var mergeDeepPropertiesKeys = ['headers', 'auth', 'proxy', 'params'];
  var defaultToConfig2Keys = [
    'baseURL', 'transformRequest', 'transformResponse', 'paramsSerializer',
    'timeout', 'timeoutMessage', 'withCredentials', 'adapter', 'responseType', 'xsrfCookieName',
    'xsrfHeaderName', 'onUploadProgress', 'onDownloadProgress', 'decompress',
    'maxContentLength', 'maxBodyLength', 'maxRedirects', 'transport', 'httpAgent',
    'httpsAgent', 'cancelToken', 'socketPath', 'responseEncoding'
  ];
  var directMergeKeys = ['validateStatus'];

  function getMergedValue(target, source) {
    if (utils.isPlainObject(target) && utils.isPlainObject(source)) {
      return utils.merge(target, source);
    } else if (utils.isPlainObject(source)) {
      return utils.merge({}, source);
    } else if (utils.isArray(source)) {
      return source.slice();
    }
    return source;
  }

  function mergeDeepProperties(prop) {
    if (!utils.isUndefined(config2[prop])) {
      config[prop] = getMergedValue(config1[prop], config2[prop]);
    } else if (!utils.isUndefined(config1[prop])) {
      config[prop] = getMergedValue(undefined, config1[prop]);
    }
  }

  utils.forEach(valueFromConfig2Keys, function valueFromConfig2(prop) {
    if (!utils.isUndefined(config2[prop])) {
      config[prop] = getMergedValue(undefined, config2[prop]);
    }
  });

  utils.forEach(mergeDeepPropertiesKeys, mergeDeepProperties);

  utils.forEach(defaultToConfig2Keys, function defaultToConfig2(prop) {
    if (!utils.isUndefined(config2[prop])) {
      config[prop] = getMergedValue(undefined, config2[prop]);
    } else if (!utils.isUndefined(config1[prop])) {
      config[prop] = getMergedValue(undefined, config1[prop]);
    }
  });

  utils.forEach(directMergeKeys, function merge(prop) {
    if (prop in config2) {
      config[prop] = getMergedValue(config1[prop], config2[prop]);
    } else if (prop in config1) {
      config[prop] = getMergedValue(undefined, config1[prop]);
    }
  });

  var axiosKeys = valueFromConfig2Keys
    .concat(mergeDeepPropertiesKeys)
    .concat(defaultToConfig2Keys)
    .concat(directMergeKeys);

  var otherKeys = Object
    .keys(config1)
    .concat(Object.keys(config2))
    .filter(function filterAxiosKeys(key) {
      return axiosKeys.indexOf(key) === -1;
    });

  utils.forEach(otherKeys, mergeDeepProperties);

  return config;
};


/***/ }),
/* 54 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * A `Cancel` is an object that is thrown when an operation is canceled.
 *
 * @class
 * @param {string=} message The message.
 */
function Cancel(message) {
  this.message = message;
}

Cancel.prototype.toString = function toString() {
  return 'Cancel' + (this.message ? ': ' + this.message : '');
};

Cancel.prototype.__CANCEL__ = true;

module.exports = Cancel;


/***/ }),
/* 55 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var Cancel = __webpack_require__(54);

/**
 * A `CancelToken` is an object that can be used to request cancellation of an operation.
 *
 * @class
 * @param {Function} executor The executor function.
 */
function CancelToken(executor) {
  if (typeof executor !== 'function') {
    throw new TypeError('executor must be a function.');
  }

  var resolvePromise;
  this.promise = new Promise(function promiseExecutor(resolve) {
    resolvePromise = resolve;
  });

  var token = this;
  executor(function cancel(message) {
    if (token.reason) {
      // Cancellation has already been requested
      return;
    }

    token.reason = new Cancel(message);
    resolvePromise(token.reason);
  });
}

/**
 * Throws a `Cancel` if cancellation has been requested.
 */
CancelToken.prototype.throwIfRequested = function throwIfRequested() {
  if (this.reason) {
    throw this.reason;
  }
};

/**
 * Returns an object that contains a new `CancelToken` and a function that, when called,
 * cancels the `CancelToken`.
 */
CancelToken.source = function source() {
  var cancel;
  var token = new CancelToken(function executor(c) {
    cancel = c;
  });
  return {
    token: token,
    cancel: cancel
  };
};

module.exports = CancelToken;


/***/ }),
/* 56 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Syntactic sugar for invoking a function and expanding an array for arguments.
 *
 * Common use case would be to use `Function.prototype.apply`.
 *
 *  ```js
 *  function f(x, y, z) {}
 *  var args = [1, 2, 3];
 *  f.apply(null, args);
 *  ```
 *
 * With `spread` this example can be re-written.
 *
 *  ```js
 *  spread(function(x, y, z) {})([1, 2, 3]);
 *  ```
 *
 * @param {Function} callback
 * @returns {Function}
 */
module.exports = function spread(callback) {
  return function wrap(arr) {
    return callback.apply(null, arr);
  };
};


/***/ }),
/* 57 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Determines whether the payload is an error thrown by Axios
 *
 * @param {*} payload The value to test
 * @returns {boolean} True if the payload is an error thrown by Axios, otherwise false
 */
module.exports = function isAxiosError(payload) {
  return (typeof payload === 'object') && (payload.isAxiosError === true);
};


/***/ }),
/* 58 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
const ExperimentationServiceBase_1 = __webpack_require__(59);
const PollingService_1 = __webpack_require__(61);
/**
 * Implementation of Feature provider that provides a polling feature, where the source can be re-fetched every x time given.
 */
class ExperimentationServiceAutoPolling extends ExperimentationServiceBase_1.ExperimentationServiceBase {
    constructor(telemetry, filterProviders, refreshRateMs, featuresTelemetryPropertyName, assignmentContextTelemetryPropertyName, telemetryEventName, storageKey, storage) {
        super(telemetry, featuresTelemetryPropertyName, assignmentContextTelemetryPropertyName, telemetryEventName, storageKey, storage);
        this.telemetry = telemetry;
        this.filterProviders = filterProviders;
        this.refreshRateMs = refreshRateMs;
        this.featuresTelemetryPropertyName = featuresTelemetryPropertyName;
        this.assignmentContextTelemetryPropertyName = assignmentContextTelemetryPropertyName;
        this.telemetryEventName = telemetryEventName;
        this.storageKey = storageKey;
        this.storage = storage;
        // Excluding 0 since it allows to turn off the auto polling.
        if (refreshRateMs < 1000 && refreshRateMs !== 0) {
            throw new Error('The minimum refresh rate for polling is 1000 ms (1 second). If you wish to deactivate this auto-polling use value of 0.');
        }
        if (refreshRateMs > 0) {
            this.pollingService = new PollingService_1.PollingService(refreshRateMs);
            this.pollingService.OnPollTick(async () => {
                await super.getFeaturesAsync();
            });
        }
    }
    init() {
        if (this.pollingService) {
            this.pollingService.StartPolling(true);
        }
        else {
            super.getFeaturesAsync();
        }
    }
    /**
     * Wrapper that will reset the polling intervals whenever the feature data is fetched manually.
     */
    async getFeaturesAsync(overrideInMemoryFeatures = false) {
        if (!this.pollingService) {
            return await super.getFeaturesAsync(overrideInMemoryFeatures);
        }
        else {
            this.pollingService.StopPolling();
            let result = await super.getFeaturesAsync(overrideInMemoryFeatures);
            this.pollingService.StartPolling();
            return result;
        }
    }
}
exports.ExperimentationServiceAutoPolling = ExperimentationServiceAutoPolling;
//# sourceMappingURL=ExperimentationServiceAutoPolling.js.map

/***/ }),
/* 59 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
const MemoryKeyValueStorage_1 = __webpack_require__(60);
/**
 * Experimentation service to provide functionality of A/B experiments:
 * - reading flights;
 * - caching current set of flights;
 * - get answer on if flights are enabled.
 */
class ExperimentationServiceBase {
    constructor(telemetry, featuresTelemetryPropertyName, assignmentContextTelemetryPropertyName, telemetryEventName, storageKey, storage) {
        this.telemetry = telemetry;
        this.featuresTelemetryPropertyName = featuresTelemetryPropertyName;
        this.assignmentContextTelemetryPropertyName = assignmentContextTelemetryPropertyName;
        this.telemetryEventName = telemetryEventName;
        this.storageKey = storageKey;
        this.storage = storage;
        this.featuresConsumed = false;
        this.cachedTelemetryEvents = [];
        this._features = {
            features: [],
            assignmentContext: '',
            configs: []
        };
        if (!this.storageKey) {
            this.storageKey = 'ABExp.Features';
        }
        if (!this.storage) {
            storage = new MemoryKeyValueStorage_1.MemoryKeyValueStorage();
        }
        this.loadCachePromise = this.loadCachedFeatureData();
        this.initializePromise = this.loadCachePromise;
        this.initialFetch = new Promise((resolve, reject) => {
            this.resolveInitialFetchPromise = resolve;
        });
    }
    get features() {
        return this._features;
    }
    set features(value) {
        this._features = value;
        /**
         * If an implementation of telemetry exists, we set the shared property.
         */
        if (this.telemetry) {
            this.telemetry.setSharedProperty(this.featuresTelemetryPropertyName, this.features.features.join(';'));
            this.telemetry.setSharedProperty(this.assignmentContextTelemetryPropertyName, this.features.assignmentContext);
        }
    }
    /**
     * Gets all the features from the provider sources (not cache).
     * It returns these features and will also update the providers to have the latest features cached.
     */
    async getFeaturesAsync(overrideInMemoryFeatures = false) {
        /**
         * If there's already a fetching promise, there's no need to call it again.
         * We return that as result.
         */
        if (this.fetchPromise != null) {
            try {
                await this.fetchPromise;
            }
            catch (_a) {
                // Fetching features threw. Can happen if not connected to the internet, e.g
            }
            return this.features;
        }
        if (!this.featureProviders || this.featureProviders.length === 0) {
            return Promise.resolve({
                features: [],
                assignmentContext: '',
                configs: []
            });
        }
        /**
         * Fetch all from providers.
         */
        this.fetchPromise = Promise.all(this.featureProviders.map(async (provider) => {
            return await provider.getFeatures();
        }));
        try {
            const featureResults = await this.fetchPromise;
            this.updateFeatures(featureResults, overrideInMemoryFeatures);
        }
        catch (_b) {
            // Fetching features threw. Can happen if not connected to the internet, e.g.
        }
        this.fetchPromise = undefined;
        if (this.resolveInitialFetchPromise) {
            this.resolveInitialFetchPromise();
            this.resolveInitialFetchPromise = undefined;
        }
        /**
         * At this point all features have been re-fetched and cache has been updated.
         * We return the cached features.
         */
        return this.features;
    }
    /**
     *
     * @param featureResults The feature results obtained from all the feature providers.
     */
    updateFeatures(featureResults, overrideInMemoryFeatures = false) {
        /**
         * if features comes as a null value, that is taken as if there aren't any features active,
         * so an empty array is defaulted.
         */
        let features = {
            features: [],
            assignmentContext: '',
            configs: []
        };
        for (let result of featureResults) {
            for (let feature of result.features) {
                if (!features.features.includes(feature)) {
                    features.features.push(feature);
                }
            }
            for (let config of result.configs) {
                const existingConfig = features.configs.find(c => c.Id === config.Id);
                if (existingConfig) {
                    existingConfig.Parameters = Object.assign(Object.assign({}, existingConfig.Parameters), config.Parameters);
                }
                else {
                    features.configs.push(config);
                }
            }
            features.assignmentContext += result.assignmentContext;
        }
        /**
         * Set the obtained feature values to the global features variable. This stores them in memory.
         */
        if (overrideInMemoryFeatures || !this.featuresConsumed) {
            this.features = features;
        }
        /**
         * If we have storage, we cache the latest results into the storage.
         */
        if (this.storage) {
            this.storage.setValue(this.storageKey, features);
        }
    }
    async loadCachedFeatureData() {
        let cachedFeatureData;
        if (this.storage) {
            cachedFeatureData = await this.storage.getValue(this.storageKey);
            // When updating from an older version of tas-client, configs may be undefined 
            if (cachedFeatureData !== undefined && cachedFeatureData.configs === undefined) {
                cachedFeatureData.configs = [];
            }
        }
        if (this.features.features.length === 0) {
            this.features = cachedFeatureData || { features: [], assignmentContext: '', configs: [] };
        }
    }
    /**
     * Returns a value indicating whether the given flight is enabled.
     * It uses the in-memory cache.
     * @param flight The flight to check.
     */
    isFlightEnabled(flight) {
        this.featuresConsumed = true;
        this.PostEventToTelemetry(flight);
        return this.features.features.includes(flight);
    }
    /**
     * Returns a value indicating whether the given flight is enabled.
     * It uses the values currently on cache.
     * @param flight The flight to check.
     */
    async isCachedFlightEnabled(flight) {
        await this.loadCachePromise;
        this.featuresConsumed = true;
        this.PostEventToTelemetry(flight);
        return this.features.features.includes(flight);
    }
    /**
     * Returns a value indicating whether the given flight is enabled.
     * It re-fetches values from the server.
     * @param flight the flight to check.
     */
    async isFlightEnabledAsync(flight) {
        const features = await this.getFeaturesAsync(true);
        this.featuresConsumed = true;
        this.PostEventToTelemetry(flight);
        return features.features.includes(flight);
    }
    /**
     * Returns the value of the treatment variable, or undefined if not found.
     * It uses the values currently in memory, so the experimentation service
     * must be initialized before calling.
     * @param config name of the config to check.
     * @param name name of the treatment variable.
     */
    getTreatmentVariable(configId, name) {
        var _a;
        this.featuresConsumed = true;
        this.PostEventToTelemetry(`${configId}.${name}`);
        const config = this.features.configs.find(c => c.Id === configId);
        return (_a = config) === null || _a === void 0 ? void 0 : _a.Parameters[name];
    }
    /**
     * Returns the value of the treatment variable, or undefined if not found.
     * It re-fetches values from the server. If checkCache is set to true and the value exists
     * in the cache, the Treatment Assignment Service is not called.
     * @param config name of the config to check.
     * @param name name of the treatment variable.
     * @param checkCache check the cache for the variable before calling the TAS.
     */
    async getTreatmentVariableAsync(configId, name, checkCache) {
        if (checkCache) {
            const _featuresConsumed = this.featuresConsumed;
            const cachedValue = this.getTreatmentVariable(configId, name);
            if (cachedValue === undefined) {
                this.featuresConsumed = _featuresConsumed;
            }
            else {
                return cachedValue;
            }
        }
        await this.getFeaturesAsync(true);
        return this.getTreatmentVariable(configId, name);
    }
    PostEventToTelemetry(flight) {
        /**
         * If this event has already been posted, we omit from posting it again.
         */
        if (this.cachedTelemetryEvents.includes(flight)) {
            return;
        }
        this.telemetry.postEvent(this.telemetryEventName, new Map([['ABExp.queriedFeature', flight]]));
        /**
         * We cache the flight so we don't post it again.
         */
        this.cachedTelemetryEvents.push(flight);
    }
    invokeInit() {
        this.init();
    }
    addFeatureProvider(...providers) {
        if (providers == null || this.featureProviders == null) {
            return;
        }
        for (let provider of providers) {
            this.featureProviders.push(provider);
        }
    }
}
exports.ExperimentationServiceBase = ExperimentationServiceBase;
//# sourceMappingURL=ExperimentationServiceBase.js.map

/***/ }),
/* 60 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
class MemoryKeyValueStorage {
    constructor() {
        this.storage = new Map();
    }
    async getValue(key, defaultValue) {
        if (this.storage.has(key)) {
            return await Promise.resolve(this.storage.get(key));
        }
        return await Promise.resolve(defaultValue || undefined);
    }
    setValue(key, value) {
        this.storage.set(key, value);
    }
}
exports.MemoryKeyValueStorage = MemoryKeyValueStorage;
//# sourceMappingURL=MemoryKeyValueStorage.js.map

/***/ }),
/* 61 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
class PollingService {
    constructor(fetchInterval) {
        this.fetchInterval = fetchInterval;
    }
    StopPolling() {
        clearInterval(this.intervalHandle);
        this.intervalHandle = undefined;
    }
    OnPollTick(callback) {
        this.onTick = callback;
    }
    StartPolling(pollImmediately = false) {
        if (this.intervalHandle) {
            this.StopPolling();
        }
        // If there's no callback, there's no point to start polling.
        if (this.onTick == null) {
            return;
        }
        if (pollImmediately) {
            this.onTick().then(() => { return; }).catch(() => { return; });
        }
        /**
         * Set the interval to start running.
         */
        this.intervalHandle = setInterval(async () => {
            await this.onTick();
        }, this.fetchInterval);
        if (this.intervalHandle.unref) { // unref is only available in Node, not the web
            this.intervalHandle.unref(); // unref is used to avoid keeping node.js alive only because of these timeouts.
        }
    }
}
exports.PollingService = PollingService;
//# sourceMappingURL=PollingService.js.map

/***/ }),
/* 62 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
class MementoKeyValueStorage {
    constructor(mementoGlobalStorage) {
        this.mementoGlobalStorage = mementoGlobalStorage;
    }
    async getValue(key, defaultValue) {
        const value = await this.mementoGlobalStorage.get(key);
        return value || defaultValue;
    }
    setValue(key, value) {
        this.mementoGlobalStorage.update(key, value);
    }
}
exports.MementoKeyValueStorage = MementoKeyValueStorage;
//# sourceMappingURL=MementoKeyValueStorage.js.map

/***/ }),
/* 63 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
class TelemetryDisabledExperimentationService {
    constructor() {
        this.initializePromise = Promise.resolve();
        this.initialFetch = Promise.resolve();
    }
    isFlightEnabled(flight) {
        return false;
    }
    isCachedFlightEnabled(flight) {
        return Promise.resolve(false);
    }
    isFlightEnabledAsync(flight) {
        return Promise.resolve(false);
    }
    getTreatmentVariable(configId, name) {
        return undefined;
    }
    getTreatmentVariableAsync(configId, name) {
        return Promise.resolve(undefined);
    }
}
exports.default = TelemetryDisabledExperimentationService;
//# sourceMappingURL=TelemetryDisabledExperimentationService.js.map

/***/ }),
/* 64 */
/***/ (function(module) {

module.exports = JSON.parse("{\"name\":\"github-authentication\",\"displayName\":\"%displayName%\",\"description\":\"%description%\",\"publisher\":\"vscode\",\"license\":\"MIT\",\"version\":\"0.0.1\",\"engines\":{\"vscode\":\"^1.41.0\"},\"icon\":\"images/icon.png\",\"enableProposedApi\":true,\"categories\":[\"Other\"],\"extensionKind\":[\"ui\",\"workspace\",\"web\"],\"activationEvents\":[\"onAuthenticationRequest:github\"],\"capabilities\":{\"virtualWorkspaces\":true,\"untrustedWorkspaces\":{\"supported\":true}},\"contributes\":{\"commands\":[{\"command\":\"github.provide-token\",\"title\":\"Manually Provide Token\"}],\"menus\":{\"commandPalette\":[{\"command\":\"github.provide-token\",\"when\":\"false\"}]},\"authentication\":[{\"label\":\"GitHub\",\"id\":\"github\"}]},\"aiKey\":\"AIF-d9b70cd4-b9f9-4d70-929b-a071c400b217\",\"main\":\"./out/extension.js\",\"browser\":\"./dist/browser/extension.js\",\"scripts\":{\"compile\":\"gulp compile-extension:github-authentication\",\"compile-web\":\"npx webpack-cli --config extension-browser.webpack.config --mode none\",\"watch\":\"gulp watch-extension:github-authentication\",\"watch-web\":\"npx webpack-cli --config extension-browser.webpack.config --mode none --watch --info-verbosity verbose\",\"vscode:prepublish\":\"npm run compile\"},\"dependencies\":{\"node-fetch\":\"2.6.1\",\"uuid\":\"8.1.0\",\"vscode-extension-telemetry\":\"0.1.7\",\"vscode-nls\":\"^4.1.2\",\"vscode-tas-client\":\"^0.1.22\"},\"devDependencies\":{\"@types/node\":\"^12.19.9\",\"@types/node-fetch\":\"^2.5.7\",\"@types/uuid\":\"8.0.0\"},\"repository\":{\"type\":\"git\",\"url\":\"https://github.com/microsoft/vscode.git\"}}");

/***/ })
/******/ ])));
//# sourceMappingURL=extension.js.map