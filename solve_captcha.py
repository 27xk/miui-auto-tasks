import base64
import json
import os
import queue
import re
import secrets
import string
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlparse

import cv2
import numpy as np
import requests
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad


API_URL = "https://verify.sec.xiaomi.com/captcha/v2/data"  # 小米验证码取数接口。
VERIFY_URL = "https://verify.sec.xiaomi.com/captcha/v2/gt/dk/verify"  # 小米二次验证接口。
APP_KEY = "3dc42a135a8d45118034d1ab68213073"  # 小米验证码应用 key。
DEFAULT_SCENE = "GROW_UP_CHECKIN"  # 默认业务场景。
DEFAULT_UID = ""  # 默认用户标识。
DEFAULT_SOURCE_URL = "https://web.vip.miui.com/"  # 默认来源页面。
DEFAULT_JS_VERSION = "0.73"  # 小米采集脚本版本。
AES_IV = b"0102030405060708"  # /data 加密固定 IV。
KEY_CHARS = string.ascii_letters + string.digits  # AES key 随机字符集。
NCNN_BIN_MAGIC = bytes.fromhex("476b3001")  # NCNN 权重文件魔数。
XIAOMI_WEBVIEW_UA = "Mozilla/5.0 (Linux; Android 16; V2546A Build/BP2A.250605.031.A3; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/148.0.7778.120 Mobile Safari/537.36XiaoMi/HybridView/ app/vipaccount/dev.260106"  # 小米 WebView UA。
ROUNDS = 10  # 完整获取-验证轮数。
URL_ATTEMPTS = 3  # 每轮获取验证码 URL 的重试次数。
SOLVE_ATTEMPTS = 5  # 每轮完整验证失败后的重试次数。
TIMEOUT = 90  # 网络和助手等待超时秒数。
PARAM_PATH = Path("yzm.param")  # yzm 模型结构文件。
BIN_PATH = Path("yzm.bin")  # yzm 模型权重文件。
MODEL_SIZE = 640  # 模型输入尺寸。
CONF_THRESHOLD = 0.25  # 检测置信度阈值。
IOU_THRESHOLD = 0.45  # NMS IoU 阈值。
SPLIT_Y = 344.0  # 主图和提示区分割线。
PROMPT_CONF = 0.7  # 提示区检测置信度阈值。
# PUBLIC_KEY_PEM：加密随机 AES key 的 RSA 公钥。
PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArxfNLkuAQ/BYHzkzVwtu
g+0abmYRBVCEScSzGxJIOsfxVzcuqaKO87H2o2wBcacD3bRHhMjTkhSEqxPjQ/FE
XuJ1cdbmr3+b3EQR6wf/cYcMx2468/QyVoQ7BADLSPecQhtgGOllkC+cLYN6Md34
Uii6U+VJf0p0q/saxUTZvhR2ka9fqJ4+6C6cOghIecjMYQNHIaNW+eSKunfFsXVU
+QfMD0q2EM9wo20aLnos24yDzRjh9HJc6xfr37jRlv1/boG/EABMG9FnTm35xWrV
R0nw3cpYF7GZg13QicS/ZwEsSd4HyboAruMxJBPvK3Jdr4ZS23bpN0cavWOJsBqZ
VwIDAQAB
-----END PUBLIC KEY-----"""
# NODE_HELPER：Node/jsdom GeeTest 助手脚本，不打开浏览器页面。
NODE_HELPER = r"""
const fs = require("fs"); // 读取本地 GeeTest SDK 文件。
const readline = require("readline"); // 逐行接收 Python 命令。
const { JSDOM } = require("jsdom"); // 提供无浏览器 DOM 环境。

const entryUrl = process.env.ENTRY_URL; // GeeTest 入口 URL。
const helperTimeoutMs = Number(process.env.HELPER_TIMEOUT_MS || 90000); // 助手超时时间。
const XIAOMI_WEBVIEW_UA = "Mozilla/5.0 (Linux; Android 16; V2546A Build/BP2A.250605.031.A3; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/148.0.7778.120 Mobile Safari/537.36XiaoMi/HybridView/ app/vipaccount/dev.260106"; // 小米 WebView UA。

function emit(obj) { // 向 Python 输出 JSON 事件。
  process.stdout.write(JSON.stringify(obj) + "\n");
}

function log(...items) { // 向 stderr 输出调试日志。
  process.stderr.write(items.map(String).join(" ") + "\n");
}

function parseJsonp(text) { // 解析 GeeTest JSONP。
  const start = text.indexOf("(");
  const end = text.lastIndexOf(")");
  if (start < 0 || end <= start) return null;
  return JSON.parse(text.slice(start + 1, end));
}

function joinImageUrl(data, challenge) { // 拼接 GeeTest 图片链接。
  const servers = data.image_servers || data.static_servers || [];
  if (!servers.length || !data.pic) return "";
  let host = String(servers[0]);
  if (!/^https?:\/\//i.test(host)) host = "https://" + host;
  return host.replace(/\/+$/, "") + "/" + String(data.pic).replace(/^\/+/, "") +
    "?challenge=" + encodeURIComponent(challenge);
}

function sleep(ms) { // 异步等待指定毫秒数。
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function setupDom() { // 构造 GeeTest SDK 运行所需 DOM。
  const dom = new JSDOM(
    "<!doctype html><html><head></head><body><div id=\"captcha\"></div></body></html>",
    { url: entryUrl, pretendToBeVisual: true, runScripts: "outside-only" }
  );
  const { window } = dom;

  window.console = {
    log: (...items) => log("[sdk]", ...items),
    error: (...items) => log("[sdk-error]", ...items),
    warn: (...items) => log("[sdk-warn]", ...items),
  };
  const addEventListener = window.EventTarget.prototype.addEventListener;
  window.EventTarget.prototype.addEventListener = function patchedAddEventListener(type, listener, options) {
    if (this && ["click", "mousedown", "mouseup", "mousemove", "touchstart", "touchend"].includes(type)) {
      if (!this.__listenerTypes) this.__listenerTypes = [];
      this.__listenerTypes.push(type);
      const originalListener = listener;
      if (typeof originalListener === "function") {
        if (!this.__listenerRecords) this.__listenerRecords = [];
        this.__listenerRecords.push({ type, listener: originalListener });
        listener = function tracedListener(event) {
          if (window.__traceClickEvents && (window.__listenerTraceCount || 0) < 60) {
            window.__listenerTraceCount = (window.__listenerTraceCount || 0) + 1;
            emit({
              event: "listener_call",
              type,
              currentClass: String(this && this.className || ""),
              currentTag: this && this.tagName || (this === window.document ? "DOCUMENT" : this === window ? "WINDOW" : ""),
              targetClass: String(event && event.target && event.target.className || ""),
              targetTag: event && event.target && event.target.tagName || "",
              x: event && event.clientX,
              y: event && event.clientY,
              which: event && event.which,
              isTrusted: event && event.isTrusted,
            });
          }
          return originalListener.apply(this, arguments);
        };
      }
    }
    return addEventListener.call(this, type, listener, options);
  };
  for (const prop of ["onclick", "onmousedown", "onmouseup", "onmousemove", "ontouchstart", "ontouchend"]) {
    const type = prop.slice(2);
    const installOn = (proto) => {
      const descriptor = Object.getOwnPropertyDescriptor(proto, prop);
      Object.defineProperty(proto, prop, {
        get() {
          return this.__geetestHandlers && this.__geetestHandlers[prop] ||
            (descriptor && descriptor.get ? descriptor.get.call(this) : null);
        },
        set(handler) {
          if (!this.__geetestHandlers) this.__geetestHandlers = {};
          this.__geetestHandlers[prop] = handler;
          if (typeof handler === "function") {
            if (!this.__listenerTypes) this.__listenerTypes = [];
            this.__listenerTypes.push(type);
            if (!this.__listenerRecords) this.__listenerRecords = [];
            this.__listenerRecords.push({ type, listener: handler });
          }
          if (descriptor && descriptor.set) {
            descriptor.set.call(this, handler);
          }
        },
      });
    };
    installOn(window.HTMLElement.prototype);
    installOn(window.Document.prototype);
  }
  Object.defineProperty(window.navigator, "userAgent", {
    get: () => XIAOMI_WEBVIEW_UA,
  });
  Object.defineProperty(window.navigator, "language", { get: () => "zh-CN" });
  Object.defineProperty(window.navigator, "platform", { get: () => "Linux armv8l" });

  const rectFor = (el) => {
    const cls = String(el.className || "");
    if (cls.includes("geetest_item") || cls.includes("geetest_fullpage_click")) {
      return { left: 0, top: 0, x: 0, y: 0, width: 344, height: 344, right: 344, bottom: 344 };
    }
    if (cls.includes("geetest_commit")) {
      return { left: 0, top: 350, x: 0, y: 350, width: 344, height: 40, right: 344, bottom: 390 };
    }
    return { left: 0, top: 0, x: 0, y: 0, width: 300, height: 300, right: 300, bottom: 300 };
  };
  Object.defineProperty(window.HTMLElement.prototype, "offsetWidth", {
    get() {
      return rectFor(this).width;
    },
  });
  Object.defineProperty(window.HTMLElement.prototype, "offsetHeight", {
    get() {
      return rectFor(this).height;
    },
  });
  window.HTMLElement.prototype.getBoundingClientRect = function getBoundingClientRect() {
    return rectFor(this);
  };
  window.document.elementFromPoint = function elementFromPoint() {
    return window.__lastClickTarget ||
      window.document.querySelector(".geetest_fullpage_click_box, .geetest_item_img, .geetest_item_wrap") ||
      window.document.body;
  };
  window.document.elementsFromPoint = function elementsFromPoint() {
    const el = window.document.elementFromPoint();
    return el ? [el] : [];
  };

  window.HTMLCanvasElement.prototype.getContext = function getContext() {
    return {
      fillRect() {},
      fillText() {},
      measureText() { return { width: 100 }; },
      getImageData() { return { data: [1, 2, 3, 4] }; },
      createBuffer() { return {}; },
      bindBuffer() {},
      bufferData() {},
      createProgram() { return {}; },
      createShader() { return {}; },
      shaderSource() {},
      compileShader() {},
      attachShader() {},
      linkProgram() {},
      useProgram() {},
      getAttribLocation() { return 0; },
      getUniformLocation() { return {}; },
      enableVertexAttribArray() {},
      vertexAttribPointer() {},
      uniform2f() {},
      clear() {},
      drawArrays() {},
      getSupportedExtensions() { return []; },
      getParameter() { return 0; },
      getContextAttributes() { return { antialias: true }; },
      getExtension() { return null; },
      getShaderPrecisionFormat() { return { precision: 23, rangeMin: 127, rangeMax: 127 }; },
    };
  };
  window.HTMLCanvasElement.prototype.toDataURL = function toDataURL() {
    return "data:image/png;base64,AAAA";
  };
  Object.defineProperty(window.HTMLImageElement.prototype, "complete", {
    get() {
      return true;
    },
  });
  Object.defineProperty(window.HTMLImageElement.prototype, "naturalWidth", {
    get() {
      return 344;
    },
  });
  Object.defineProperty(window.HTMLImageElement.prototype, "naturalHeight", {
    get() {
      return 384;
    },
  });
  function triggerImageLoad(img) {
    setTimeout(() => {
      if (typeof img.onload === "function") img.onload.call(img, new window.Event("load"));
      img.dispatchEvent(new window.Event("load"));
    }, 0);
  }
  const imageSrc = Object.getOwnPropertyDescriptor(window.HTMLImageElement.prototype, "src");
  Object.defineProperty(window.HTMLImageElement.prototype, "src", {
    get() {
      return imageSrc && imageSrc.get ? imageSrc.get.call(this) : this.getAttribute("src") || "";
    },
    set(value) {
      if (imageSrc && imageSrc.set) {
        imageSrc.set.call(this, value);
      } else {
        this.setAttribute("src", value);
      }
      triggerImageLoad(this);
    },
  });
  const imageOnload = Object.getOwnPropertyDescriptor(window.HTMLImageElement.prototype, "onload");
  Object.defineProperty(window.HTMLImageElement.prototype, "onload", {
    get() {
      return this.__geetestOnload || (imageOnload && imageOnload.get ? imageOnload.get.call(this) : null);
    },
    set(handler) {
      this.__geetestOnload = handler;
      if (imageOnload && imageOnload.set) {
        imageOnload.set.call(this, handler);
      }
      if (typeof handler === "function" && this.src) {
        setTimeout(() => handler.call(this, new window.Event("load")), 0);
      }
    },
  });
  const imageAddEventListener = window.HTMLImageElement.prototype.addEventListener;
  window.HTMLImageElement.prototype.addEventListener = function patchedImageAddEventListener(type, listener, options) {
    const result = imageAddEventListener.call(this, type, listener, options);
    if (type === "load" && typeof listener === "function" && this.src) {
      setTimeout(() => listener.call(this, new window.Event("load")), 0);
    }
    return result;
  };
  const imageSetAttribute = window.HTMLImageElement.prototype.setAttribute;
  window.HTMLImageElement.prototype.setAttribute = function patchedImageSetAttribute(name, value) {
    const result = imageSetAttribute.call(this, name, value);
    if (String(name).toLowerCase() === "src" && value) {
      triggerImageLoad(this);
    }
    return result;
  };
  window.Image = function Image(width, height) {
    const img = window.document.createElement("img");
    if (width) img.width = width;
    if (height) img.height = height;
    return img;
  };
  window.Image.prototype = window.HTMLImageElement.prototype;

  return window;
}

function installScriptInterceptor(window, challenge) { // 拦截 SDK 动态脚本请求。
  const originalAppend = window.Element.prototype.appendChild;
  let pendingClickResponse = null;
  window.__releaseClickCaptcha = function releaseClickCaptcha() {
    if (!pendingClickResponse) return false;
    const { text, el, src } = pendingClickResponse;
    pendingClickResponse = null;
    emit({ event: "release_click_jsonp", url: src });
    try {
      window.eval(text);
    } catch (err) {
      emit({ event: "warn", message: "script eval failed: " + err.message, url: src });
    }
    el.loaded = true;
    if (typeof el.onload === "function") el.onload();
    if (typeof el.onreadystatechange === "function") el.onreadystatechange();
    return true;
  };

  window.Element.prototype.appendChild = function appendChild(el) {
    const ret = originalAppend.call(this, el);
    if (el && el.tagName === "SCRIPT" && el.src) {
      const src = el.src;
      fetch(src, { headers: { Referer: entryUrl, "User-Agent": XIAOMI_WEBVIEW_UA } })
        .then((response) => response.text())
        .then((text) => {
          let ajaxSuccessData = null;
          try {
            const jsonp = parseJsonp(text);
            if (jsonp && src.includes("/get.php?is_next=true") && jsonp.status === "success") {
              const data = jsonp.data || {};
              emit({
                event: "image",
                request_url: src,
                image_url: joinImageUrl(data, challenge),
                data,
              });
              pendingClickResponse = { text, el, src };
              return;
            }
            if (jsonp && src.includes("/ajax.php")) {
              emit({ event: "ajax", request_url: src, data: jsonp.data || {}, status: jsonp.status });
              if (jsonp.status === "success" && jsonp.data && jsonp.data.result === "success") {
                ajaxSuccessData = jsonp.data;
              }
            }
          } catch (err) {
            emit({ event: "warn", message: "jsonp parse failed: " + err.message, url: src });
          }

          try {
            window.eval(text);
          } catch (err) {
            emit({ event: "warn", message: "script eval failed: " + err.message, url: src });
          }
          if (ajaxSuccessData) {
            window.__lastAjaxSuccessData = ajaxSuccessData;
            if (typeof window.__scheduleGeetestSuccessFallback === "function") {
              window.__scheduleGeetestSuccessFallback(ajaxSuccessData);
            }
          }
          el.loaded = true;
          if (typeof el.onload === "function") el.onload();
          if (typeof el.onreadystatechange === "function") el.onreadystatechange();
        })
        .catch((err) => {
          emit({ event: "warn", message: "script fetch failed: " + err.message, url: src });
          if (typeof el.onerror === "function") el.onerror(err);
        });
    }
    return ret;
  };
}

function fireMouse(window, el, type, x, y) { // 派发鼠标事件。
  window.__lastClickTarget = el;
  const event = new window.MouseEvent(type, {
    bubbles: true,
    cancelable: true,
    view: window,
    clientX: x,
    clientY: y,
    pageX: x,
    pageY: y,
    screenX: x,
    screenY: y,
    button: 0,
    buttons: type === "mouseup" ? 0 : 1,
  });
  for (const key of ["offsetX", "offsetY", "layerX", "layerY"]) {
    try {
      Object.defineProperty(event, key, { get: () => (key.endsWith("X") ? x : y) });
    } catch (_) {}
  }
  for (const [key, value] of [
    ["which", 1],
    ["pageX", x],
    ["pageY", y],
    ["x", x],
    ["y", y],
  ]) {
    try {
      Object.defineProperty(event, key, { get: () => value });
    } catch (_) {}
  }
  try {
    Object.defineProperty(event, "srcElement", { get: () => el });
  } catch (_) {}
  try {
    Object.defineProperty(event, "isTrusted", { get: () => true });
  } catch (_) {}
  el.dispatchEvent(event);
  if (window.__trustedReplay) {
    replayTrustedListeners(window, el, type, x, y);
  }
}

function fireTouch(window, el, type, x, y) { // 派发触摸事件。
  window.__lastClickTarget = el;
  const point = {
    identifier: 1,
    target: el,
    clientX: x,
    clientY: y,
    pageX: x,
    pageY: y,
    screenX: x,
    screenY: y,
  };
  const event = new window.Event(type, { bubbles: true, cancelable: true });
  for (const [key, value] of [
    ["touches", type === "touchend" ? [] : [point]],
    ["targetTouches", type === "touchend" ? [] : [point]],
    ["changedTouches", [point]],
    ["srcElement", el],
    ["isTrusted", true],
  ]) {
    try {
      Object.defineProperty(event, key, { get: () => value });
    } catch (_) {}
  }
  el.dispatchEvent(event);
  if (window.__trustedReplay) {
    replayTrustedListeners(window, el, type, x, y);
  }
}

function makeTrustedEvent(window, el, current, type, x, y) { // 构造可信事件回放对象。
  const touchPoint = {
    identifier: 1,
    target: el,
    clientX: x,
    clientY: y,
    pageX: x,
    pageY: y,
    screenX: x,
    screenY: y,
  };
  const event = {
    type,
    bubbles: true,
    cancelable: true,
    target: el,
    srcElement: el,
    currentTarget: current,
    view: window,
    clientX: x,
    clientY: y,
    pageX: x,
    pageY: y,
    screenX: x,
    screenY: y,
    x,
    y,
    offsetX: x,
    offsetY: y,
    layerX: x,
    layerY: y,
    button: 0,
    buttons: type === "mouseup" ? 0 : 1,
    which: 1,
    isTrusted: true,
    touches: type === "touchend" ? [] : [touchPoint],
    targetTouches: type === "touchend" ? [] : [touchPoint],
    changedTouches: [touchPoint],
    defaultPrevented: false,
    preventDefault() { this.defaultPrevented = true; },
    stopPropagation() { this.cancelBubble = true; },
    stopImmediatePropagation() { this.cancelBubble = true; this.immediatePropagationStopped = true; },
    composedPath() {
      const path = [];
      let node = el;
      while (node) {
        path.push(node);
        node = node.parentElement;
      }
      path.push(window.document, window);
      return path;
    },
  };
  return event;
}

function replayTrustedListeners(window, el, type, x, y) { // 回放绑定监听器。
  const targets = [];
  let current = el;
  while (current) {
    targets.push(current);
    current = current.parentElement;
  }
  targets.push(window.document, window);
  for (const target of targets) {
    const records = (target && target.__listenerRecords || []).filter((item) => item.type === type);
    for (const record of records) {
      try {
        const trustedEvent = makeTrustedEvent(window, el, target, type, x, y);
        record.listener.call(target, trustedEvent);
      } catch (err) {
        emit({ event: "warn", message: "trusted listener replay failed: " + err.message, type });
      }
    }
  }
}

async function waitForElement(window, selectors, timeoutMs) { // 等待 DOM 元素出现。
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    for (const selector of selectors) {
      const el = window.document.querySelector(selector);
      if (el) return el;
    }
    await sleep(100);
  }
  return null;
}

function describeElement(el) { // 描述单个元素状态。
  if (!el) return null;
  return {
    tagName: el.tagName,
    className: String(el.className || ""),
    text: (el.textContent || "").trim().slice(0, 80),
    listeners: el.__listenerTypes || [],
  };
}

function describePath(el) { // 描述元素父级路径。
  const path = [];
  let current = el;
  while (current && current.tagName && path.length < 8) {
    path.push(describeElement(current));
    current = current.parentElement;
  }
  return path;
}

function clickState(window) { // 收集点击相关 DOM 状态。
  const doc = window.document;
  const commit = doc.querySelector(".geetest_commit, .geetest_submit, .geetest_click_submit, .geetest_fullpage_commit");
  return {
    commit: describeElement(commit),
    selectedCount: doc.querySelectorAll(".geetest_selected, .geetest_item_selected, .geetest_click_mark, .geetest_fullpage_click_point, .geetest_point, .geetest_big_mark").length,
    markClasses: Array.from(doc.querySelectorAll("[class*='point'], [class*='mark'], [class*='select']"))
      .map((el) => String(el.className || ""))
      .filter(Boolean)
      .slice(0, 20),
    documentListeners: doc.__listenerTypes || [],
    windowListeners: window.__listenerTypes || [],
    bodyListeners: doc.body.__listenerTypes || [],
    geetestClasses: Array.from(doc.querySelectorAll("[class*='geetest']"))
      .map((el) => String(el.className || ""))
      .filter(Boolean)
      .slice(0, 80),
  };
}

function forceClickMarks(window, target, points) { // 兜底写入点击标记。
  const doc = window.document;
  for (const point of points) {
    const marker = doc.createElement("div");
    marker.className = "geetest_fullpage_click_point geetest_click_mark geetest_selected";
    marker.style.left = `${Number(point.x)}px`;
    marker.style.top = `${Number(point.y)}px`;
    marker.setAttribute("data-x", String(Number(point.x)));
    marker.setAttribute("data-y", String(Number(point.y)));
    target.appendChild(marker);
  }
  const commit = doc.querySelector(".geetest_commit, .geetest_submit, .geetest_click_submit, .geetest_fullpage_commit");
  if (commit) {
    commit.className = String(commit.className || "").replace(/\bgeetest_disable\b/g, "").trim();
  }
  emit({ event: "forced_marks", state: clickState(window) });
}

function objectKeysSummary(obj, depth = 1, seen = new Set()) { // 压缩输出对象键结构。
  if (!obj || (typeof obj !== "object" && typeof obj !== "function") || seen.has(obj)) return null;
  seen.add(obj);
  const out = {};
  for (const key of Object.getOwnPropertyNames(obj).slice(0, 80)) {
    let value;
    try {
      value = obj[key];
    } catch (_) {
      continue;
    }
    const type = typeof value;
    if (type === "function") {
      out[key] = "[function]";
    } else if (value && type === "object") {
      out[key] = depth > 0 ? objectKeysSummary(value, depth - 1, seen) : "[object]";
    } else {
      out[key] = type;
    }
  }
  return out;
}

function listenerSourceSummary(window) { // 汇总监听器源码片段。
  const summarize = (target, name) => (target.__listenerRecords || []).map((record, index) => ({
    name,
    index,
    type: record.type,
    source: String(record.listener).slice(0, 600),
  }));
  return [
    ...summarize(window.document, "document"),
    ...summarize(window, "window"),
  ].slice(0, 40);
}

async function clickFullpage(window) { // 触发 GeeTest 全屏点选模式。
  const el = await waitForElement(
    window,
    [".geetest_radar_tip", ".geetest_radar_btn", ".geetest_holder"],
    15000
  );
  if (!el) {
    emit({ event: "error", message: "fullpage button not found" });
    return;
  }
  fireMouse(window, el, "mousemove", 150, 150);
  fireMouse(window, el, "mousedown", 150, 150);
  fireMouse(window, el, "mouseup", 150, 150);
  fireMouse(window, el, "click", 150, 150);
}

async function applyClicks(window, points) { // 应用模型识别出的点击坐标。
  const released = typeof window.__releaseClickCaptcha === "function" && window.__releaseClickCaptcha();
  emit({ event: "clicks_start", count: points.length, released });
  emit({ event: "captcha_summary", summary: objectKeysSummary(window.__captcha, 2) });
  emit({ event: "listener_sources", sources: listenerSourceSummary(window) });
  window.__traceClickEvents = false;
  window.__listenerTraceCount = 0;
  window.__trustedReplay = false;
  let target = await waitForElement(
    window,
    [".geetest_item", ".geetest_item_img", ".geetest_item_wrap"],
    15000
  );
  if (!target) {
    target = await waitForElement(window, [".geetest_fullpage_click_box"], 5000);
  }
  const initialCommit = await waitForElement(
    window,
    [".geetest_commit", ".geetest_submit", ".geetest_click_submit", ".geetest_fullpage_commit"],
    15000
  );
  if (!target) {
    const classes = Array.from(window.document.querySelectorAll("*"))
      .map((el) => String(el.className || ""))
      .filter(Boolean)
      .slice(0, 120);
    emit({ event: "error", message: "click target not found", classes });
    return;
  }
  if (!initialCommit) {
    emit({ event: "error", message: "initial commit button not found", state: clickState(window) });
    return;
  }
  await sleep(500);
  emit({ event: "click_target", target: describeElement(target), path: describePath(target), state: clickState(window) });

  for (const point of points) {
    const x = Number(point.x);
    const y = Number(point.y);
    emit({ event: "click_point", x, y });
    fireMouse(window, target, "mousemove", x, y);
    fireMouse(window, target, "mousedown", x, y);
    fireTouch(window, target, "touchstart", x, y);
    await sleep(80);
    fireTouch(window, target, "touchend", x, y);
    fireMouse(window, target, "mouseup", x, y);
    fireMouse(window, target, "click", x, y);
    await sleep(350);
    emit({ event: "click_state", state: clickState(window) });
  }

  await sleep(600);
  if (clickState(window).selectedCount === 0) {
    forceClickMarks(window, target, points);
    await sleep(100);
  }
  const commit = await waitForElement(
    window,
    [".geetest_commit", ".geetest_submit", ".geetest_click_submit", ".geetest_fullpage_commit"],
    5000
  );
  if (!commit) {
    const classes = Array.from(window.document.querySelectorAll("*"))
      .map((el) => String(el.className || ""))
      .filter((name) => name.includes("geetest"))
      .slice(0, 160);
    emit({ event: "error", message: "commit button not found", classes });
    return;
  }
  emit({ event: "commit_target", target: describeElement(commit), state: clickState(window) });
  window.__trustedReplay = true;
  fireMouse(window, commit, "mousemove", 170, 370);
  fireMouse(window, commit, "mousedown", 170, 370);
  fireMouse(window, commit, "mouseup", 170, 370);
  fireMouse(window, commit, "click", 170, 370);
  window.__trustedReplay = false;
  emit({ event: "submitted" });
}

async function main() { // 启动 jsdom、加载 SDK 并处理命令。
  const parsed = new URL(entryUrl);
  const gt = parsed.searchParams.get("c");
  const challenge = parsed.searchParams.get("l");
  const window = setupDom();
  installScriptInterceptor(window, challenge);

  const scripts = [
    "https://static.geetest.com/static/js/geetest.6.0.9.js",
    "https://static.geetest.com/static/js/fullpage.9.2.0-guwyxh.js",
    "https://static.geetest.com/static/js/click.3.1.2.js",
  ];
  for (const url of scripts) {
    const text = await (await fetch(url, { headers: { Referer: entryUrl, "User-Agent": XIAOMI_WEBVIEW_UA } })).text();
    window.eval(text);
  }

  const captcha = new window.Geetest({
    gt,
    challenge,
    product: "bind",
    lang: "zh-cn",
    https: true,
    protocol: "https://",
    width: "100%",
    api_server: "api.geetest.com",
    offline: false,
    new_captcha: true,
    type: "fullpage",
  });
  window.__captcha = captcha;
  window.__geetestSuccessEmitted = false;
  window.__lastAjaxSuccessData = null;
  window.__emitGeetestSuccess = async function emitGeetestSuccess(ajaxSuccessData, source) {
    if (window.__geetestSuccessEmitted) return;
    const data = ajaxSuccessData || window.__lastAjaxSuccessData || {};
    for (let index = 0; index < 20; index += 1) {
      let sdkValidate = {};
      try {
        if (window.__captcha && typeof window.__captcha.getValidate === "function") {
          sdkValidate = window.__captcha.getValidate() || {};
        }
      } catch (err) {
        emit({ event: "warn", message: "getValidate failed: " + err.message });
      }
      const validate = sdkValidate.geetest_validate || data.validate;
      const challengeValue = sdkValidate.geetest_challenge;
      const seccode = sdkValidate.geetest_seccode || (validate ? validate + "|jordan" : undefined);
      if ((validate && challengeValue && seccode) || index === 19) {
        window.__geetestSuccessEmitted = true;
        emit({
          event: "geetest_success",
          source,
          validate,
          challenge: challengeValue,
          seccode,
          score: data.score,
          data,
          sdk_validate: sdkValidate,
        });
        return;
      }
      await sleep(100);
    }
  };
  window.__scheduleGeetestSuccessFallback = function scheduleGeetestSuccessFallback(ajaxSuccessData) {
    setTimeout(() => {
      if (!window.__geetestSuccessEmitted) {
        window.__emitGeetestSuccess(ajaxSuccessData, "ajax_fallback");
      }
    }, 1500);
  };

  captcha.onReady(() => {
    setTimeout(() => {
      if (typeof captcha.verify === "function") {
        captcha.verify();
      } else {
        clickFullpage(window);
      }
    }, 300);
  });
  captcha.onSuccess(() => {
    window.__emitGeetestSuccess(window.__lastAjaxSuccessData, "sdk_onSuccess");
  });
  captcha.onError((err) => {
    if (err && err.code === "error_108") {
      emit({ event: "warn", message: "ignored geetest image-load warning", detail: err });
      return;
    }
    emit({ event: "error", message: "geetest error", detail: err });
  });
  captcha.onFail((err) => emit({ event: "error", message: "geetest fail", detail: err }));
  captcha.appendTo("#captcha");

  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  rl.on("line", (line) => {
    if (!line.trim()) return;
    let cmd;
    try {
      cmd = JSON.parse(line);
    } catch (err) {
      emit({ event: "error", message: "invalid command json: " + err.message });
      return;
    }
    if (cmd.cmd === "clicks") {
      emit({ event: "command", cmd: "clicks", count: (cmd.points || []).length });
      applyClicks(window, cmd.points || []).catch((err) => {
        emit({ event: "error", message: "apply clicks failed: " + (err && err.stack ? err.stack : String(err)) });
      });
    }
  });

  setTimeout(() => emit({ event: "error", message: "helper timeout" }), helperTimeoutMs);
}

main().catch((err) => {
  emit({ event: "error", message: err && err.stack ? err.stack : String(err) });
});
"""


def now_ms() -> int:  # 返回当前毫秒时间戳。
    return round(time.time() * 1000)


def make_aes_key() -> str:  # 生成 16 位随机 AES key。
    return "".join(secrets.choice(KEY_CHARS) for _ in range(16))


def aes_encrypt(key: str, plaintext: str) -> str:  # AES-CBC 加密明文并转 base64。
    cipher = AES.new(key.encode("utf-8"), AES.MODE_CBC, AES_IV)
    encrypted = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    return base64.b64encode(encrypted).decode("utf-8")


def rsa_encrypt_key(key: str) -> str:  # RSA 加密 AES key。
    public_key = RSA.import_key(PUBLIC_KEY_PEM)
    cipher = PKCS1_v1_5.new(public_key)
    encoded_key = base64.b64encode(key.encode("utf-8"))
    encrypted = cipher.encrypt(encoded_key)
    return base64.b64encode(encrypted).decode("utf-8")


def build_headers() -> dict[str, str]:  # 生成小米 /data 请求头。
    return {
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
        "Cache-Control": "no-cache",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "https://web.vip.miui.com",
        "Pragma": "no-cache",
        "Referer": "https://web.vip.miui.com/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site",
        "User-Agent": XIAOMI_WEBVIEW_UA,
        "X-Requested-With": "com.xiaomi.vipaccount",
        "sec-ch-ua": '"Chromium";v="148", "Android WebView";v="148", "Not/A)Brand";v="99"',
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
    }


def build_plain_payload(  # 生成小米 /data 明文环境载荷。
    uid: str = DEFAULT_UID,
    scene: str = DEFAULT_SCENE,
    source_url: str = DEFAULT_SOURCE_URL,
    js_version: str = DEFAULT_JS_VERSION,
    now_ms: int | None = None,
    collection_duration_ms: int = 220,
    nonce_seconds: int | None = None,
    nonce_random: int | None = None,
) -> str:
    timestamp_ms = now_ms if now_ms is not None else globals()["now_ms"]()
    timestamp_seconds = nonce_seconds if nonce_seconds is not None else round(time.time())
    random_nonce = (
        nonce_random
        if nonce_random is not None
        else secrets.randbelow(900_000_000) + 100_000_000
    )
    env = {
        "p1": "0.1",
        "p2": "mobile-Webkit537",
        "p3": "Linux armv8l",
        "p4": "Gecko",
        "p5": "zh-CN",
        "p6": "Netscape",
        "p7": "Mozilla",
        "p8": True,
        "p9": XIAOMI_WEBVIEW_UA,
        "p10": 480,
        "p11": timestamp_ms,
        "p12": 0,
        "p13": 0,
        "p14": 0,
        "p15": 0,
        "p16": 1024,
        "p17": 768,
        "p18": source_url,
        "p19": "",
        "p20": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "p21": "",
        "p22": 0,
        "p23": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "p24": "",
        "p25": "1e97c10212dc8cd7ff2a55b48d15410f0e5f6b2e",
        "p26": "2be88ca4242c76e8253ac62474851065032d6833",
        "p28": "",
        "p29": 47,
        "p30": "",
        "p31": "",
        "p32": js_version,
        "p33": [],
        "p34": source_url,
    }
    action = {f"a{i}": [] for i in range(1, 15)}
    action["a1"] = [1024, 768]
    payload = {
        "type": 1,
        "startTs": timestamp_ms,
        "endTs": timestamp_ms + collection_duration_ms,
        "env": env,
        "action": action,
        "force": False,
        "talkBack": False,
        "uid": uid,
        "nonce": {"t": timestamp_seconds, "r": random_nonce},
        "version": "2.0",
        "scene": scene,
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def build_post_data(uid: str = DEFAULT_UID, scene: str = DEFAULT_SCENE) -> dict[str, str]:  # 生成 /data 加密表单。
    key = make_aes_key()
    plaintext = build_plain_payload(uid=uid, scene=scene)
    return {
        "s": rsa_encrypt_key(key),
        "d": aes_encrypt(key, plaintext),
        "a": scene,
    }


def extract_captcha_url(response_json: dict[str, Any]) -> tuple[str, str]:  # 提取 GeeTest 入口 URL。
    data = response_json.get("data") or {}
    if isinstance(data, dict) and data.get("url"):
        return str(data.get("id", "")), str(data["url"])

    if isinstance(data, dict) and data.get("token"):
        raise RuntimeError("server returned token directly; no captcha URL required")

    if isinstance(data, dict):
        message = data.get("message") or data.get("status")
    else:
        message = None
    message = message or response_json.get("msg") or response_json
    raise RuntimeError(f"captcha url not found: {message}")


def fetch_captcha_url(  # 请求小米 /data 并重试取得验证码入口。
    uid: str = DEFAULT_UID,
    scene: str = DEFAULT_SCENE,
    attempts: int = 3,
    timeout: int = 20,
) -> tuple[str, str, dict[str, Any]]:
    last_error: Exception | None = None
    for _ in range(attempts):
        response = requests.post(
            API_URL,
            params={"k": APP_KEY, "locale": "zh_CN", "_t": str(now_ms())},
            headers=build_headers(),
            data=build_post_data(uid=uid, scene=scene),
            timeout=timeout,
        )
        response.raise_for_status()
        result = response.json()
        try:
            event_id, url = extract_captcha_url(result)
            return event_id, url, result
        except RuntimeError as exc:
            last_error = exc
            message = str(exc)
            if "invalid nonce" not in message:
                break
    raise RuntimeError(str(last_error) if last_error else "captcha url not found")


def parse_jsonp(text: str) -> dict[str, Any]:  # 解析 JSONP 响应。
    match = re.match(r"^\s*[\w$]+\((.*)\)\s*;?\s*$", text, flags=re.S)
    if not match:
        raise ValueError("invalid JSONP response")
    return json.loads(match.group(1))


def build_geetest_image_url(data: dict[str, Any], challenge: str) -> str:  # 拼接 GeeTest 图片 URL。
    servers = data.get("image_servers") or data.get("static_servers") or []
    pic = data.get("pic")
    if not servers or not pic:
        raise ValueError("geetest image data does not contain image_servers/pic")
    host = str(servers[0])
    if not re.match(r"^https?://", host, flags=re.I):
        host = "https://" + host
    return f"{host.rstrip('/')}/{str(pic).lstrip('/')}?challenge={quote(challenge, safe='')}"


def ordered_click_targets(  # 按提示区顺序生成实际点击坐标。
    detections: list[dict[str, Any]],
    split_y: float = 344.0,
    prompt_conf: float = 0.0,
) -> list[dict[str, Any]]:
    prompts = sorted(
        [
            item
            for item in detections
            if float(item["box"][1]) >= split_y and float(item["score"]) >= prompt_conf
        ],
        key=lambda item: float(item["box"][0]),
    )
    main_items = [item for item in detections if float(item["box"][1]) < split_y]
    targets = []
    for prompt in prompts:
        class_id = int(prompt["class_id"])
        candidates = [item for item in main_items if int(item["class_id"]) == class_id]
        if not candidates:
            raise RuntimeError(f"no main-image detection for prompt class {class_id}")
        best = max(candidates, key=lambda item: float(item["score"]))
        x1, y1, x2, y2 = [float(value) for value in best["box"]]
        targets.append(
            {
                "class_id": class_id,
                "score": float(best["score"]),
                "x": (x1 + x2) / 2,
                "y": (y1 + y2) / 2,
                "box": best["box"],
            }
        )
    if not targets:
        raise RuntimeError("no prompt detections found in bottom prompt area")
    return targets


def query_params(url: str) -> dict[str, str]:  # 读取 URL 查询参数。
    return {key: values[0] for key, values in parse_qs(urlparse(url).query).items()}


def build_xiaomi_verify_params(  # 组装小米二次验证表单参数。
    entry_url: str,
    fallback_challenge: str,
    validate: str,
    geetest_event: dict[str, Any] | None = None,
    callback: str | None = None,
) -> dict[str, str]:
    params = query_params(entry_url)
    event = geetest_event or {}
    sdk_validate = event.get("sdk_validate") or {}
    challenge = (
        event.get("challenge")
        or sdk_validate.get("geetest_challenge")
        or fallback_challenge
    )
    seccode = (
        event.get("seccode")
        or sdk_validate.get("geetest_seccode")
        or f"{validate}|jordan"
    )
    verify_params = {
        "k": params["k"],
        "locale": params.get("locale", "zh_cn"),
        "e": params["e"],
        "challenge": str(challenge),
        "seccode": str(seccode),
    }
    if callback:
        verify_params["callback"] = callback
    return verify_params


def download_image(session: requests.Session, url: str, timeout: int) -> np.ndarray:  # 下载验证码图片到内存。
    response = session.get(
        url,
        headers={
            "Accept": "image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5",
            "Referer": "https://static-verify.sec.xiaomi.com/",
            "User-Agent": XIAOMI_WEBVIEW_UA,
        },
        timeout=timeout,
    )
    response.raise_for_status()
    image = cv2.imdecode(np.frombuffer(response.content, dtype=np.uint8), cv2.IMREAD_COLOR)
    if image is None:
        raise RuntimeError(f"failed to decode captcha image: {url}")
    return image


def is_ncnn_bin_magic(header: bytes) -> bool:  # 判断 NCNN 权重魔数。
    return header[:4] == NCNN_BIN_MAGIC


def validate_model_files(param_path: Path, bin_path: Path) -> None:  # 校验 NCNN 模型文件。
    if not param_path.exists():
        raise FileNotFoundError(
            f"missing NCNN param file: {param_path}. "
            "yzm.bin only contains weights; NCNN also needs the matching .param graph file."
        )
    if not bin_path.exists():
        raise FileNotFoundError(f"missing NCNN bin file: {bin_path}")
    if not is_ncnn_bin_magic(bin_path.read_bytes()[:4]):
        raise ValueError(f"{bin_path} does not look like an NCNN .bin weights file")


def parse_param_io(param_path: Path) -> tuple[str, list[str]]:  # 从 .param 自动识别输入输出 blob。
    layers = []
    lines = param_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    for line in lines[2:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        layer_type = parts[0]
        try:
            bottom_count = int(parts[2])
            top_count = int(parts[3])
        except ValueError:
            continue
        bottoms = parts[4 : 4 + bottom_count]
        tops = parts[4 + bottom_count : 4 + bottom_count + top_count]
        layers.append((layer_type, bottoms, tops))

    inputs = [tops[0] for layer_type, _, tops in layers if layer_type == "Input" and tops]
    if not inputs:
        raise ValueError(f"no Input layer found in {param_path}")

    produced = []
    consumed = set()
    for _, bottoms, tops in layers:
        consumed.update(bottoms)
        produced.extend(tops)
    outputs = [name for name in produced if name not in consumed]
    if not outputs:
        raise ValueError(f"no output blobs found in {param_path}")
    return inputs[0], outputs


def letterbox(image: np.ndarray, size: int) -> tuple[np.ndarray, float, tuple[int, int]]:  # 等比缩放并填充到模型尺寸。
    height, width = image.shape[:2]
    scale = min(size / width, size / height)
    resized_width = int(round(width * scale))
    resized_height = int(round(height * scale))
    resized = cv2.resize(image, (resized_width, resized_height), interpolation=cv2.INTER_LINEAR)
    canvas = np.full((size, size, 3), 114, dtype=np.uint8)
    pad_x = (size - resized_width) // 2
    pad_y = (size - resized_height) // 2
    canvas[pad_y : pad_y + resized_height, pad_x : pad_x + resized_width] = resized
    return canvas, scale, (pad_x, pad_y)


def sigmoid(values: np.ndarray) -> np.ndarray:  # Sigmoid 激活。
    return 1.0 / (1.0 + np.exp(-values))


def softmax(values: np.ndarray, axis: int = -1) -> np.ndarray:  # Softmax 激活。
    shifted = values - np.max(values, axis=axis, keepdims=True)
    exp = np.exp(shifted)
    return exp / np.sum(exp, axis=axis, keepdims=True)


def box_iou(a: np.ndarray, b: np.ndarray) -> float:  # 计算两个框的 IoU。
    x1 = max(float(a[0]), float(b[0]))
    y1 = max(float(a[1]), float(b[1]))
    x2 = min(float(a[2]), float(b[2]))
    y2 = min(float(a[3]), float(b[3]))
    inter = max(0.0, x2 - x1) * max(0.0, y2 - y1)
    area_a = max(0.0, float(a[2] - a[0])) * max(0.0, float(a[3] - a[1]))
    area_b = max(0.0, float(b[2] - b[0])) * max(0.0, float(b[3] - b[1]))
    union = area_a + area_b - inter
    return inter / union if union > 0 else 0.0


def nms(detections: list[dict], iou_threshold: float) -> list[dict]:  # 对检测结果做 NMS。
    if not detections:
        return []
    detections = sorted(detections, key=lambda item: item["score"], reverse=True)
    kept = []
    while detections:
        current = detections.pop(0)
        kept.append(current)
        remaining = []
        current_box = np.array(current["box"], dtype=np.float32)
        for item in detections:
            other = np.array(item["box"], dtype=np.float32)
            if item["class_id"] != current["class_id"] or box_iou(current_box, other) < iou_threshold:
                remaining.append(item)
        detections = remaining
    return kept


def decode_yolov8_dfl_outputs(  # 解码 YOLOv8 DFL 输出为原图坐标框。
    outputs: list[np.ndarray],
    image_shape: tuple[int, int],
    input_size: int,
    scale: float,
    pad: tuple[int, int],
    conf_threshold: float,
    iou_threshold: float,
    reg_max: int = 16,
) -> list[dict]:
    image_h, image_w = image_shape
    pad_x, pad_y = pad
    detections = []
    bins = np.arange(reg_max, dtype=np.float32)

    for output in outputs:
        raw = np.asarray(output, dtype=np.float32)
        if raw.ndim == 4 and raw.shape[0] == 1:
            raw = raw[0]
        if raw.ndim != 3:
            raise ValueError(f"unsupported DFL output shape: {tuple(output.shape)}")
        height, width, channels = raw.shape
        bbox_channels = 4 * reg_max
        if channels <= bbox_channels:
            raise ValueError(f"DFL output has too few channels: {tuple(output.shape)}")

        stride = input_size / max(height, width)
        box_logits = raw[:, :, :bbox_channels].reshape(height, width, 4, reg_max)
        distances = (softmax(box_logits, axis=-1) * bins).sum(axis=-1)
        scores = raw[:, :, bbox_channels:]
        if float(scores.max(initial=0.0)) > 1.0 or float(scores.min(initial=0.0)) < 0.0:
            scores = sigmoid(scores)

        best_class = np.argmax(scores, axis=-1)
        best_score = np.max(scores, axis=-1)
        ys, xs = np.where(best_score >= conf_threshold)
        for y, x in zip(ys.tolist(), xs.tolist()):
            center_x = (x + 0.5) * stride
            center_y = (y + 0.5) * stride
            left, top, right, bottom = distances[y, x] * stride
            box = np.array(
                [
                    center_x - left,
                    center_y - top,
                    center_x + right,
                    center_y + bottom,
                ],
                dtype=np.float32,
            )
            box[[0, 2]] = (box[[0, 2]] - pad_x) / scale
            box[[1, 3]] = (box[[1, 3]] - pad_y) / scale
            box[[0, 2]] = np.clip(box[[0, 2]], 0, image_w)
            box[[1, 3]] = np.clip(box[[1, 3]], 0, image_h)
            detections.append(
                {
                    "class_id": int(best_class[y, x]),
                    "score": float(best_score[y, x]),
                    "box": [float(value) for value in box],
                }
            )
    return nms(detections, iou_threshold)


def run_ncnn_image(image: np.ndarray, param_path: Path | str = PARAM_PATH, bin_path: Path | str = BIN_PATH, size: int = MODEL_SIZE, conf: float = CONF_THRESHOLD, iou: float = IOU_THRESHOLD, input_name: str | None = None, output_names: str | list[str] | None = None) -> list[dict[str, Any]]:  # 使用 ncnn 对内存图片执行推理。
    param_path, bin_path = Path(param_path), Path(bin_path)
    validate_model_files(param_path, bin_path)
    detected_input, detected_outputs = parse_param_io(param_path)
    input_name = input_name or detected_input
    output_names = [name.strip() for name in output_names.split(",") if name.strip()] if isinstance(output_names, str) else list(output_names or detected_outputs)

    try:
        import ncnn
    except ImportError as exc:
        raise RuntimeError("missing dependency: pip install ncnn") from exc

    net = ncnn.Net()
    net.load_param(str(param_path))
    net.load_model(str(bin_path))

    model_image, scale, pad_values = letterbox(image, size)
    rgb = cv2.cvtColor(model_image, cv2.COLOR_BGR2RGB)
    mat = ncnn.Mat.from_pixels(rgb, ncnn.Mat.PixelType.PIXEL_RGB, size, size)
    mat.substract_mean_normalize([], [1 / 255.0, 1 / 255.0, 1 / 255.0])

    ex = net.create_extractor()
    ex.input(input_name, mat)
    outputs = []
    for output_name in output_names:
        ret, out = ex.extract(output_name)
        if ret != 0:
            raise RuntimeError(f"extract failed for output blob {output_name}: {ret}")
        outputs.append(np.array(out))
    return decode_yolov8_dfl_outputs(
        outputs,
        image.shape[:2],
        size,
        scale,
        pad_values,
        conf,
        iou,
    )


def run_ncnn(source: Path | str, param_path: Path | str = PARAM_PATH, bin_path: Path | str = BIN_PATH, size: int = MODEL_SIZE, conf: float = CONF_THRESHOLD, iou: float = IOU_THRESHOLD, input_name: str | None = None, output_names: str | list[str] | None = None) -> list[dict[str, Any]]:  # 使用 ncnn 推理单个图片文件且不保存结果。
    image = cv2.imread(str(source))
    if image is None:
        raise RuntimeError(f"failed to read image: {source}")
    return run_ncnn_image(image, param_path=param_path, bin_path=bin_path, size=size, conf=conf, iou=iou, input_name=input_name, output_names=output_names)


def run_model(image: np.ndarray, param_path: Path | str = PARAM_PATH, bin_path: Path | str = BIN_PATH, size: int = MODEL_SIZE, conf: float = CONF_THRESHOLD, iou: float = IOU_THRESHOLD) -> list[dict[str, Any]]:  # 推理单张内存验证码并返回检测框。
    return run_ncnn_image(image, param_path=param_path, bin_path=bin_path, size=size, conf=conf, iou=iou)


def node_module_path_env(cwd: Path | None = None, existing: str | None = None) -> str:  # 拼接 Node 模块搜索路径。
    root = cwd or Path.cwd()
    paths = []
    for current in (root, *root.parents):
        candidate = current / "node_modules"
        if candidate.exists():
            paths.append(str(candidate))
    if existing:
        paths.extend(part for part in existing.split(os.pathsep) if part)
    return os.pathsep.join(dict.fromkeys(paths))


class GeetestHelper:  # 管理 Node/jsdom GeeTest 助手进程。
    def __init__(self, entry_url: str, timeout: int):  # 保存助手启动参数和缓冲区。
        self.entry_url = entry_url
        self.timeout = timeout
        self.script_path: Path | None = None
        self.process: subprocess.Popen[str] | None = None
        self._stdout_queue: queue.Queue[str] = queue.Queue()
        self._stderr_queue: queue.Queue[str] = queue.Queue()
        self._stderr_tail: list[str] = []
        self._event_history: list[dict[str, Any]] = []
        self._reader_threads: list[threading.Thread] = []

    def __enter__(self) -> "GeetestHelper":  # 写入临时助手脚本并启动 Node。
        handle = tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix=".cjs",
            prefix="_geetest_helper_",
            delete=False,
        )
        try:
            handle.write(NODE_HELPER)
            self.script_path = Path(handle.name)
        finally:
            handle.close()

        env = os.environ.copy()
        env["ENTRY_URL"] = self.entry_url
        env["HELPER_TIMEOUT_MS"] = str((self.timeout + 20) * 1000)
        if node_path := node_module_path_env(existing=env.get("NODE_PATH")):
            env["NODE_PATH"] = node_path
        self.process = subprocess.Popen(
            ["node", str(self.script_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            cwd=str(Path.cwd()),
            env=env,
            bufsize=1,
        )
        self._start_reader_threads()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # 停止助手进程并删除临时脚本。
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        if self.script_path:
            try:
                self.script_path.unlink()
            except OSError:
                pass

    def _start_reader_threads(self) -> None:  # 启动 stdout/stderr 后台读取线程。
        if not self.process:
            return
        if self.process.stdout:
            self._reader_threads.append(
                threading.Thread(
                    target=self._read_stream,
                    args=(self.process.stdout, self._stdout_queue),
                    daemon=True,
                )
            )
        if self.process.stderr:
            self._reader_threads.append(
                threading.Thread(
                    target=self._read_stream,
                    args=(self.process.stderr, self._stderr_queue),
                    daemon=True,
                )
            )
        for thread in self._reader_threads:
            thread.start()

    @staticmethod
    def _read_stream(stream: Any, target: queue.Queue[str]) -> None:  # 持续读取子进程输出。
        try:
            while True:
                line = stream.readline()
                if line == "":
                    break
                target.put(line)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            target.put(f"[reader-error] {exc}\n")

    def _drain_stderr(self) -> None:  # 抽取 stderr 最近日志。
        while True:
            try:
                line = self._stderr_queue.get_nowait()
            except queue.Empty:
                break
            line = line.rstrip()
            if line:
                self._stderr_tail.append(line)
                self._stderr_tail = self._stderr_tail[-80:]

    def _remember_event(self, event: dict[str, Any]) -> None:  # 记录最近助手事件。
        self._event_history.append(event)
        self._event_history = self._event_history[-20:]

    def _diagnostic_tail(self) -> str:  # 生成超时/异常诊断信息。
        self._drain_stderr()
        parts = []
        if self._event_history:
            parts.append("recent_events=" + json.dumps(self._event_history[-20:], ensure_ascii=False))
        if self._stderr_tail:
            parts.append("stderr=" + "\n".join(self._stderr_tail[-30:]))
        return "; ".join(parts)

    def send(self, payload: dict[str, Any]) -> None:  # 向助手发送 JSON 命令。
        if not self.process or not self.process.stdin:
            raise RuntimeError("helper process is not running")
        self.process.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
        self.process.stdin.flush()

    def read_event(self, wanted: set[str], timeout: int) -> dict[str, Any]:  # 等待指定助手事件。
        if not self.process:
            raise RuntimeError("helper process is not running")
        deadline = time.monotonic() + timeout
        while True:
            self._drain_stderr()
            if self.process.poll() is not None:
                raise RuntimeError(f"helper exited with {self.process.returncode}: {self._diagnostic_tail()}")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                detail = self._diagnostic_tail()
                if detail:
                    raise TimeoutError(f"timed out waiting for {sorted(wanted)}; {detail}")
                raise TimeoutError(f"timed out waiting for {sorted(wanted)}")
            try:
                line = self._stdout_queue.get(timeout=min(0.1, remaining))
            except queue.Empty:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            name = event.get("event")
            self._remember_event(event)
            if name == "error":
                raise RuntimeError(json.dumps(event, ensure_ascii=False))
            if name in wanted:
                return event


def verify_xiaomi(  # 提交 GeeTest validate 完成小米二次验证。
    session: requests.Session,
    entry_url: str,
    challenge: str,
    validate: str,
    timeout: int,
    geetest_event: dict[str, Any] | None = None,
) -> dict[str, Any]:
    entry_params = query_params(entry_url)
    body = build_xiaomi_verify_params(
        entry_url=entry_url,
        fallback_challenge=challenge,
        validate=validate,
        geetest_event=geetest_event,
    )
    body.pop("k", None)
    body.pop("locale", None)
    body.pop("callback", None)
    response = session.post(
        VERIFY_URL,
        params={
            "k": entry_params["k"],
            "locale": entry_params.get("locale", "zh_cn"),
            "_t": str(now_ms()),
        },
        data=body,
        headers={
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
            "Cache-Control": "no-cache",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://static-verify.sec.xiaomi.com",
            "Pragma": "no-cache",
            "Referer": entry_url,
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "User-Agent": XIAOMI_WEBVIEW_UA,
            "X-Requested-With": "com.xiaomi.vipaccount",
            "sec-ch-ua": '"Chromium";v="148", "Android WebView";v="148", "Not/A)Brand";v="99"',
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"',
        },
        timeout=timeout,
    )
    response.raise_for_status()
    try:
        return parse_jsonp(response.text)
    except ValueError:
        return response.json()


def solve_once(uid: str = DEFAULT_UID, scene: str = DEFAULT_SCENE, url_attempts: int = URL_ATTEMPTS, timeout: int = TIMEOUT, param_path: Path | str = PARAM_PATH, bin_path: Path | str = BIN_PATH, size: int = MODEL_SIZE, conf: float = CONF_THRESHOLD, iou: float = IOU_THRESHOLD, split_y: float = SPLIT_Y, prompt_conf: float = PROMPT_CONF) -> dict[str, Any]:  # 执行一次获取、识别、点击、验证全流程。
    session = requests.Session()

    # 1. 请求小米 /data，得到 GeeTest check URL。
    event_id, entry_url, entry_result = fetch_captcha_url(
        uid=uid,
        scene=scene,
        attempts=url_attempts,
        timeout=timeout,
    )
    params = query_params(entry_url)
    challenge = params["l"]

    with GeetestHelper(entry_url, timeout) as helper:
        # 2. jsdom 跑 GeeTest SDK，只取图片链接，不打开浏览器页面。
        image_event = helper.read_event({"image"}, timeout=timeout)
        image_url = image_event.get("image_url") or build_geetest_image_url(image_event["data"], challenge)
        image = download_image(session, image_url, timeout)

        # 3. 本地 yzm/ncnn 识别提示区顺序，并回放点击坐标。
        detections = run_model(image, param_path=param_path, bin_path=bin_path, size=size, conf=conf, iou=iou)
        targets = ordered_click_targets(detections, split_y=split_y, prompt_conf=prompt_conf)
        helper.send({"cmd": "clicks", "points": [{"x": item["x"], "y": item["y"]} for item in targets]})
        geetest_event = helper.read_event({"geetest_success"}, timeout=timeout)

    # 4. 使用 GeeTest validate 完成小米二次校验，拿最终 token。
    xiaomi_result = verify_xiaomi(
        session=session,
        entry_url=entry_url,
        challenge=challenge,
        validate=geetest_event["validate"],
        timeout=timeout,
        geetest_event=geetest_event,
    )
    token = ((xiaomi_result.get("data") or {}).get("token"))
    if not token:
        raise RuntimeError(
            "xiaomi verify did not return token: "
            + json.dumps(xiaomi_result, ensure_ascii=False, separators=(",", ":"))
        )
    return {
        "event_id": event_id,
        "entry_url": entry_url,
        "entry_result": entry_result,
        "challenge": challenge,
        "image_url": image_url,
        "detections": detections,
        "targets": targets,
        "geetest": geetest_event,
        "xiaomi": xiaomi_result,
        "token": token,
    }


def format_compact_result(result: dict[str, Any]) -> str:  # 格式化最终三行精简日志。
    clicks = ",".join(f"({float(item['x']):.1f},{float(item['y']):.1f})" for item in result["targets"])
    verify = json.dumps(result["xiaomi"], ensure_ascii=False, separators=(",", ":"))
    return f"image_url={result['image_url']}\nclicks={clicks}\nverify={verify}"


def main(rounds: int = ROUNDS, solve_attempts: int = SOLVE_ATTEMPTS, **solve_kwargs: Any) -> int:  # 按预设重试并输出最终结果。
    last_error: Exception | None = None
    for _round in range(1, rounds + 1):
        for attempt in range(1, solve_attempts + 1):
            try:
                print(format_compact_result(solve_once(**solve_kwargs)))
                break
            except Exception as exc:  # pylint: disable=broad-exception-caught
                last_error = exc
                if attempt < solve_attempts:
                    time.sleep(1)
        else:
            print(f"ERROR: {last_error}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
